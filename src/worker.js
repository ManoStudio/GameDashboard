import adminStyle from "../static/admin.css";
import adminScript from "../static/admin-ui.js";
import { renderAdmin } from "./admin-pages.js";
import { MODERN_THEME_STYLE } from "./modern-theme.js";
import { startGoogle, googleCallback, exchangeDesktop } from "./google-auth.js";

const CHANNELS = ["dev", "qa", "live", "deprecated"];
const USER_ROLES = ["admin", "dev", "QA", "viewer"];
const PASSWORD_HASH_ITERATIONS = 100000;

const encoder = new TextEncoder();

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const artifact = url.pathname.match(/^\/api\/artifacts\/(.+)$/);
      if (artifact && (request.method === "GET" || request.method === "HEAD")) {
        const key = decodeURIComponent(artifact[1]);
        const signed = key.startsWith("builds/") && await validArtifactSignature(env, key, url.searchParams);
        // A valid artifact token already authorizes this exact object. Avoid a
        // D1 session lookup even when the Launcher also sends its login cookie.
        const user = signed ? null : await currentUser(request, env);
        if (user?.auth_type === "project-token") return json({ error: "Project tokens only permit build uploads." }, 403);
        return await downloadArtifact(request, env, user, key, signed, ctx);
      }
      // Schema is managed by D1 migrations. Bootstrap only when someone signs in.
      if (request.method === "GET" && url.pathname === "/api/auth/google/start") {
        await bootstrapAdmin(env);
      }
      const user = await currentUser(request, env);
      const route = await dispatch(request, env, url, user, ctx);
      return route || notFound();
    } catch (error) {
      return html(`<h1>Server Error</h1><pre>${escapeHtml(error.stack || error.message)}</pre>`, 500);
    }
  },
};

async function dispatch(request, env, url, user, ctx) {
  const path = url.pathname;
  const method = request.method;

  // Project tokens are upload credentials, not Dashboard administrator sessions.
  if (user?.auth_type === "project-token") {
    const upload = path.match(/^\/api\/projects\/([^/]+)\/uploads\/(?:init|[^/]+\/(?:complete|status|progress|fail))$/);
    const permitted = method === "GET" && ["/api/me", "/api/projects"].includes(path)
      || upload && upload[1] === user.project_id && (method === "POST" && !path.endsWith('/status') || method === "GET" && path.endsWith('/status'));
    if (!permitted) return json({ error: "Token only permits uploads to its assigned project." }, 403);
  }

  const tokenRoute = path.match(/^\/api\/projects\/([^/]+)\/tokens(?:\/([^/]+))?$/);
  if (tokenRoute) {
    const denied = requireTokenAdmin(request, user);
    if (denied) return denied;
    const projectId = tokenRoute[1];
    if (!await getProject(env, projectId, user)) return json({ error: "project not found" }, 404);
    if (method === "GET" && !tokenRoute[2]) return tokenJson(await listProjectTokens(env, projectId));
    if (method === "POST" && !tokenRoute[2]) return createProjectToken(request, env, user, projectId);
    if (method === "DELETE" && tokenRoute[2]) return revokeProjectToken(env, projectId, tokenRoute[2]);
    return json({ error: "method not allowed" }, 405);
  }

  const discordRoute = path.match(/^\/api\/projects\/([^/]+)\/discord-webhook(\/test)?$/);
  if (discordRoute) {
    const denied = requireTokenAdmin(request, user, "Discord notification settings");
    if (denied) return denied;
    const projectId = discordRoute[1];
    const project = await getProject(env, projectId, user);
    if (!project) return json({ error: "project not found" }, 404);
    if (method === "GET" && !discordRoute[2]) return tokenJson(await discordWebhookState(env, projectId));
    if (method === "PUT" && !discordRoute[2]) return saveDiscordWebhook(request, env, user, projectId);
    if (method === "DELETE" && !discordRoute[2]) {
      await env.DB.prepare("DELETE FROM project_discord_webhooks WHERE project_id = ?").bind(projectId).run();
      return tokenJson(await discordWebhookState(env, projectId));
    }
    if (method === "POST" && discordRoute[2]) return testDiscordWebhook(env, project, url.origin);
    return json({ error: "method not allowed" }, 405);
  }

  if (path === "/login" && method === "GET") return loginPage(url.searchParams.get("error") || "");
  if (path === "/api/auth/google/start" && method === "GET") return startGoogle(request, env);
  if (path === "/api/auth/google/callback" && method === "GET") return googleCallback(request, env);
  if (path === "/api/auth/desktop/exchange" && method === "POST") return exchangeDesktop(request, env);
  if (path === "/logout" && method === "POST") return logout(request, env);
  if (path === "/api/auth/login" && method === "POST") return env.LEGACY_PASSWORD_LOGIN_ENABLED === "true" ? loginJson(request, env) : json({ error: "Update Mano Launcher and sign in with Google." }, 410);
  if (path === "/api/auth/logout" && method === "POST") return logoutJson(request, env);
  if (path === "/api/me" && method === "GET") return requireLogin(user, true) || json({ user: describeUser(user) });
  if (path === "/api/launcher/library" && method === "GET") return requireLogin(user, true) || json(await launcherLibrary(env, user));
  if (path === "/api/launcher/latest" && method === "GET") return launcherLatest(request, env);
  if (path === "/api/launcher/installer" && method === "GET") return launcherInstaller(env);
  if (path === "/api/launcher/history" && method === "GET") return launcherHistory(request, env);
  if (path === "/" && method === "GET") return requireLogin(user) || dashboard(request, env, user);

  if (path === "/api/bug-reports" && method === "POST") return requireLogin(user, true) || createBugReport(request, env, user);
  if (path === "/api/bug-reports" && method === "GET") return requireRole(user, "admin", "dev", "QA", true) || listBugReportsJson(request, env, user);
  const bugReportLog = path.match(/^\/api\/bug-reports\/([^/]+)\/log$/);
  if (bugReportLog && method === "GET") return requireRole(user, "admin", "dev", "QA", true) || downloadBugReportLog(env, user, decodeURIComponent(bugReportLog[1]), url.searchParams.get("preview") === "1");
  const bugReportSnapshot = path.match(/^\/api\/bug-reports\/([^/]+)\/snapshot$/);
  if (bugReportSnapshot && method === "GET") return requireRole(user, "admin", "dev", "QA", true) || downloadBugReportSnapshot(env, user, decodeURIComponent(bugReportSnapshot[1]));
  const bugReportStatus = path.match(/^\/bug-reports\/([^/]+)\/status$/);
  if (bugReportStatus && method === "POST") return requireRole(user, "admin", "dev", "QA") || updateBugReportStatus(request, env, user, decodeURIComponent(bugReportStatus[1]));

  if (path === "/projects" && method === "POST") return requireRole(user, "admin") || createProject(request, env);
  const projectUpdate = path.match(/^\/projects\/([^/]+)$/);
  if (projectUpdate && method === "POST") return requireRole(user, "admin") || updateProject(request, env, projectUpdate[1]);
  const projectDelete = path.match(/^\/projects\/([^/]+)\/delete$/);
  if (projectDelete && method === "POST") return requireRole(user, "admin") || deleteProject(request, env, projectDelete[1]);

  if (path === "/users" && method === "POST") return requireRole(user, "admin") || upsertUser(request, env);
  const userRole = path.match(/^\/users\/([^/]+)\/role$/);
  if (userRole && method === "POST") return requireRole(user, "admin") || updateUserRole(request, env, user, decodeURIComponent(userRole[1]));
  const userDelete = path.match(/^\/users\/([^/]+)\/delete$/);
  if (userDelete && method === "POST") return requireRole(user, "admin") || deleteUser(request, env, user, decodeURIComponent(userDelete[1]));

  if (path === "/api/projects" && method === "GET") return json(await listProjects(env, user));
  const apiBuilds = path.match(/^\/api\/projects\/([^/]+)\/builds$/);
  if (apiBuilds && method === "GET") return json(await listBuilds(env, apiBuilds[1], user, url.origin));
  if (apiBuilds && method === "POST") return requireRole(user, "admin", "dev", true) || legacyTooLargeResponse();

  const apiDelete = path.match(/^\/api\/projects\/([^/]+)$/);
  if (apiDelete && method === "DELETE") return requireRole(user, "admin", true) || deleteProjectJson(env, apiDelete[1]);

  const initUpload = path.match(/^\/api\/projects\/([^/]+)\/uploads\/init$/);
  if (initUpload && method === "POST") return requireRole(user, "admin", "dev", true) || initUploadSession(request, env, user, initUpload[1]);
  const uploadQueue = path.match(/^\/api\/projects\/([^/]+)\/upload-queue(?:\/(reorder))?$/);
  if (uploadQueue) {
    const denied = requireRole(user, "admin", "dev", true);
    if (denied) return denied;
    if (!await getProject(env, uploadQueue[1], user)) return tokenJson({ error: "project not found" }, 404);
    if (method === "GET" && !uploadQueue[2]) return tokenJson(await listUploadQueue(env, uploadQueue[1]));
    if (method === "POST" && uploadQueue[2]) return reorderUploadQueue(request, env, user, uploadQueue[1]);
    return tokenJson({ error: "method not allowed" }, 405);
  }
  const uploadState = path.match(/^\/api\/projects\/([^/]+)\/uploads\/([^/]+)\/(status|progress|fail)$/);
  if (uploadState) {
    const denied = requireRole(user, "admin", "dev", true) || uploadMutationGuard(request, user);
    if (denied) return denied;
    return updateUploadSession(request, env, user, uploadState[1], uploadState[2], uploadState[3]);
  }
  const completeUpload = path.match(/^\/api\/projects\/([^/]+)\/uploads\/([^/]+)\/complete$/);
  if (completeUpload && method === "POST") return requireRole(user, "admin", "dev", true) || completeUploadSession(request, env, user, completeUpload[1], completeUpload[2], ctx);

  const artifact = path.match(/^\/api\/artifacts\/(.+)$/);
  if (artifact && (method === "GET" || method === "HEAD")) return downloadArtifact(request, env, user, decodeURIComponent(artifact[1]));

  const manifest = path.match(/^\/builds\/([^/]+)\/manifest$/) || path.match(/^\/api\/builds\/([^/]+)\/manifest$/);
  if (manifest && method === "GET") return buildManifest(request, env, manifest[1], user);
  const channel = path.match(/^\/builds\/([^/]+)\/channel$/) || path.match(/^\/api\/builds\/([^/]+)\/channel$/);
  if (channel && (method === "POST" || method === "PATCH")) return requireRole(user, "admin", "dev", "QA", true) || updateBuildChannel(request, env, user, channel[1]);
  const rollback = path.match(/^\/builds\/([^/]+)\/rollback$/);
  if (rollback && method === "POST") return requireRole(user, "admin") || rollbackBuild(env, rollback[1]);
  const buildDelete = path.match(/^\/builds\/([^/]+)\/delete$/);
  if (buildDelete && method === "POST") return requireRole(user, "admin", "dev") || deleteBuild(env, buildDelete[1]);
  const apiBuildDelete = path.match(/^\/api\/builds\/([^/]+)$/);
  if (apiBuildDelete && method === "DELETE") return requireRole(user, "admin", "dev", true) || deleteBuildJson(env, apiBuildDelete[1]);
  const buildDetails = path.match(/^\/api\/builds\/([^/]+)\/details$/);
  if (buildDetails && method === "PATCH") return requireRole(user, "admin", "dev", true) || updateBuildDetails(request, env, user, buildDetails[1]);

  return null;
}

async function bootstrapAdmin(env) {
  if (!env.ADMIN_EMAIL) return;
  const email = env.ADMIN_EMAIL.trim().toLowerCase();
  const existing = await env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(email).first();
  if (existing) return;
  const now = nowIso();
  await env.DB.prepare(
    "INSERT INTO users (email, role, password_hash, created_at, updated_at) VALUES (?, 'admin', ?, ?, ?)"
  ).bind(email, "", now, now).run();
}

async function currentUser(request, env) {
  // An invalid/revoked Bearer credential must never fall back to a cookie.
  if (request.headers.has("Authorization")) return apiTokenUser(request, env);
  const token = cookie(request, "sid");
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const session = await env.DB.prepare(
    "SELECT sessions.email, users.role FROM sessions JOIN users ON users.email = sessions.email WHERE token_hash = ? AND expires_at > ?"
  ).bind(tokenHash, nowIso()).first();
  return session ? { email: session.email, role: session.role, auth_type: "session" } : null;
}

function describeUser(user) {
  if (!user) return null;
  return {
    email: user.email,
    role: user.role,
    visible_channels: visibleChannelsForRole(user.role),
    runtime_environments: runtimeEnvironmentsForRole(user.role),
    ...(user.auth_type === "project-token" ? { project_id: user.project_id, upload_channels: user.allowed_channels } : {}),
  };
}

async function apiTokenUser(request, env) {
  const match = (request.headers.get("Authorization") || "").match(/^Bearer (\S+)$/i);
  if (!match) return null;
  const token = match[1];
  if (env.DASHBOARD_API_TOKEN && await equalApiSecrets(token, env.DASHBOARD_API_TOKEN)) {
    return { email: "api-token", role: "admin", auth_type: "legacy-token" };
  }
  if (!/^gd_[0-9a-f]{64}$/.test(token)) return null;
  const now = nowIso();
  const row = await env.DB.prepare(
    "SELECT project_api_tokens.* FROM project_api_tokens JOIN projects ON projects.id = project_api_tokens.project_id WHERE token_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)"
  ).bind(await sha256Hex(token), now).first();
  if (!row) return null;
  const allowedChannels = JSON.parse(row.channels_json);
  if (!Array.isArray(allowedChannels) || !allowedChannels.length || allowedChannels.some(channel => !["dev", "qa", "live"].includes(channel))) return null;
  // Limit metadata writes for repeated CI requests; authentication is always fresh.
  if (!row.last_used_at || Date.parse(now) - Date.parse(row.last_used_at) > 300_000) {
    await env.DB.prepare("UPDATE project_api_tokens SET last_used_at = ? WHERE id = ? AND revoked_at IS NULL")
      .bind(now, row.id).run();
  }
  return { email: `project-token:${row.id}`, role: "dev", auth_type: "project-token", token_id: row.id, project_id: row.project_id, allowed_channels: allowedChannels };
}

async function equalApiSecrets(provided, expected) {
  const [a, b] = await Promise.all([provided, expected].map(value => crypto.subtle.digest("SHA-256", encoder.encode(value))));
  if (crypto.subtle.timingSafeEqual) return crypto.subtle.timingSafeEqual(a, b);
  // Node's Web Crypto lacks the Workers extension; use native HMAC verification.
  const key = await crypto.subtle.importKey("raw", b, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  return crypto.subtle.verify("HMAC", key, await crypto.subtle.sign("HMAC", key, a), b);
}

function requireTokenAdmin(request, user, resource = "API tokens") {
  if (!user) return json({ error: "unauthorized" }, 401);
  if (user.role !== "admin" || user.auth_type !== "session") return json({ error: `Sign in as an administrator to manage ${resource}.` }, 403);
  if (request.method !== "GET") {
    if (request.headers.get("Origin") !== new URL(request.url).origin) return json({ error: "Invalid request origin." }, 403);
    if (!(request.headers.get("Content-Type") || "").toLowerCase().startsWith("application/json")) return json({ error: "Use application/json." }, 415);
  }
  return null;
}

function tokenJson(data, status = 200) {
  return json(data, status, { "Cache-Control": "private, no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff" });
}

async function listProjectTokens(env, projectId) {
  const { results } = await env.DB.prepare(
    "SELECT id, project_id, name, token_prefix, channels_json, created_by, created_at, expires_at, last_used_at, revoked_at FROM project_api_tokens WHERE project_id = ? ORDER BY created_at DESC"
  ).bind(projectId).all();
  return (results || []).map(({ channels_json, ...row }) => ({ ...row, channels: JSON.parse(channels_json) }));
}

async function createProjectToken(request, env, user, projectId) {
  let payload;
  try { payload = await readLimitedJson(request, 4096); }
  catch (error) { return tokenJson({ error: error instanceof RangeError ? "Token settings are too large." : "Invalid JSON." }, 400); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return tokenJson({ error: "Invalid token settings." }, 400);
  const name = typeof payload.name === "string" ? payload.name.trim() : "";
  if (!name || name.length > 100) return tokenJson({ error: "Enter a token name of 1–100 characters." }, 400);
  const channels = payload.channels;
  if (!Array.isArray(channels) || !channels.length || channels.length > 3 || channels.some(channel => !["dev", "qa", "live"].includes(channel))) {
    return tokenJson({ error: "Select at least one upload channel: dev, qa, or live." }, 400);
  }
  const days = payload.expires_in_days ?? 90;
  if (![0, 30, 90, 365].includes(days)) return tokenJson({ error: "Choose an expiry of 0, 30, 90, or 365 days." }, 400);
  const now = nowIso();
  const token = `gd_${bytesToHex(crypto.getRandomValues(new Uint8Array(32)))}`;
  const id = `token-${crypto.randomUUID()}`;
  const expiresAt = days ? new Date(Date.parse(now) + days * 86400_000).toISOString() : null;
  const uniqueChannels = [...new Set(channels)];
  await env.DB.prepare(
    "INSERT INTO project_api_tokens (id, project_id, name, token_hash, token_prefix, channels_json, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, projectId, name, await sha256Hex(token), token.slice(0, 11), JSON.stringify(uniqueChannels), user.email, now, expiresAt).run();
  return tokenJson({ id, project_id: projectId, name, token, token_prefix: token.slice(0, 11), channels: uniqueChannels, expires_at: expiresAt, created_at: now, created_by: user.email, last_used_at: null, revoked_at: null }, 201);
}

async function revokeProjectToken(env, projectId, tokenId) {
  const row = await env.DB.prepare("SELECT id FROM project_api_tokens WHERE id = ? AND project_id = ?").bind(tokenId, projectId).first();
  if (!row) return tokenJson({ error: "token not found" }, 404);
  await env.DB.prepare("UPDATE project_api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND project_id = ?")
    .bind(nowIso(), tokenId, projectId).run();
  return tokenJson({ id: tokenId, revoked: true });
}

function normalizeDiscordWebhook(value) {
  if (typeof value !== "string" || value.length > 512) throw new Error("Invalid Discord webhook URL.");
  const url = new URL(value.trim());
  if (url.protocol !== "https:" || !["discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"].includes(url.hostname) || url.port || url.username || url.password || url.hash) throw new Error("Invalid Discord webhook URL.");
  if (!/^\/api(?:\/v\d{1,2})?\/webhooks\/\d{16,22}\/[A-Za-z0-9._-]{20,200}\/?$/.test(url.pathname)) throw new Error("Invalid Discord webhook URL.");
  const params = [...url.searchParams];
  if (params.length > 1 || params.some(([key, val]) => key !== "thread_id" || !/^\d{16,22}$/.test(val))) throw new Error("Invalid Discord webhook URL.");
  url.hostname = "discord.com";
  url.pathname = url.pathname.replace(/\/$/, "");
  return url.toString();
}

async function discordWebhookState(env, projectId) {
  const row = await env.DB.prepare("SELECT * FROM project_discord_webhooks WHERE project_id = ?").bind(projectId).first();
  // Posting credentials are write-only from the UI, never returned to any client.
  return {
    configured: Boolean(row?.webhook_url), enabled: Boolean(row?.enabled),
    channels: row ? JSON.parse(row.channels_json) : [...CHANNELS],
    last_attempt_at: row?.last_attempt_at || null, last_sent_at: row?.last_sent_at || null,
    last_error: row?.last_error || null,
  };
}

async function saveDiscordWebhook(request, env, user, projectId) {
  let payload;
  try { payload = await readLimitedJson(request, 4096); }
  catch { return tokenJson({ error: "Invalid or oversized webhook settings." }, 400); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || typeof payload.enabled !== "boolean" || !Array.isArray(payload.channels) || !payload.channels.length || payload.channels.length > 4 || payload.channels.some(channel => !CHANNELS.includes(channel)) || typeof payload.webhook_url !== "string") {
    return tokenJson({ error: "Enter a webhook URL, enable/disable notifications, and select upload channels." }, 400);
  }
  const existing = await env.DB.prepare("SELECT webhook_url FROM project_discord_webhooks WHERE project_id = ?").bind(projectId).first();
  let webhookUrl = existing?.webhook_url || null;
  if (payload.webhook_url.trim()) {
    try { webhookUrl = normalizeDiscordWebhook(payload.webhook_url); }
    catch { return tokenJson({ error: "Use an HTTPS Discord incoming webhook URL. Only an optional thread_id query is supported." }, 400); }
  }
  if (payload.enabled && !webhookUrl) return tokenJson({ error: "Add a Discord webhook URL before enabling notifications." }, 400);
  await env.DB.prepare(
    "INSERT INTO project_discord_webhooks (project_id, webhook_url, enabled, channels_json, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(project_id) DO UPDATE SET webhook_url = excluded.webhook_url, enabled = excluded.enabled, channels_json = excluded.channels_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at, last_attempt_at = CASE WHEN webhook_url IS excluded.webhook_url THEN last_attempt_at ELSE NULL END, last_sent_at = CASE WHEN webhook_url IS excluded.webhook_url THEN last_sent_at ELSE NULL END, last_error = CASE WHEN webhook_url IS excluded.webhook_url THEN last_error ELSE NULL END"
  ).bind(projectId, webhookUrl, payload.enabled ? 1 : 0, JSON.stringify([...new Set(payload.channels)]), user.email, nowIso()).run();
  return tokenJson(await discordWebhookState(env, projectId));
}

function discordText(value, max = 1024) {
  const text = String(value || "").replace(/[\\`*_{}\[\]()<>~|]/g, "\\$&");
  return text.length <= max ? text : text.slice(0, max - 1).replace(/[\uD800-\uDBFF]$/, "") + "…";
}

function discordReleaseSummary(value) {
  const lines = String(value || "").trim().split(/\r?\n/);
  const formatted = lines.slice(0, 10).map(line => {
    const heading = line.match(/^#{1,6}\s+(.+)$/);
    if (heading) return `**${discordText(heading[1], 120)}**`;
    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    if (bullet) return `• ${discordText(bullet[1], 180)}`;
    if (/^\s*(`{3,}|~{3,})/.test(line)) return "";
    return discordText(line, 200);
  });
  const visible = [];
  let length = 0;
  for (const line of formatted) {
    if (length + line.length + 1 > 900) break;
    visible.push(line); length += line.length + 1;
  }
  const summary = visible.join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return summary + (visible.length < formatted.length || lines.length > 10 ? "\n…" : "");
}

function discordCode(value, max = 150) {
  const text = String(value || "").replace(/`/g, "ˋ").replace(/[\r\n\t]/g, " ");
  return `\`${text.slice(0, max).replace(/[\uD800-\uDBFF]$/, "")}\``;
}

function discordUploadMessage(project, build, baseUrl, { test = false } = {}) {
  const url = new URL("/", baseUrl);
  url.search = new URLSearchParams({ view: build.id ? "build" : "builds", project: project.id, ...(build.id ? { build: build.id } : {}) }).toString();
  const projectUrl = new URL("/", baseUrl);
  projectUrl.search = new URLSearchParams({ view: "dashboard", project: project.id }).toString();
  const size = Number.isFinite(Number(build.total_size)) ? Math.max(0, Number(build.total_size)) : 0;
  const sizeText = size >= 1073741824 ? `${(size / 1073741824).toFixed(2)} GB`
    : size >= 1048576 ? `${(size / 1048576).toFixed(1)} MB`
    : size >= 1024 ? `${(size / 1024).toFixed(1)} KB` : `${size} B`;
  const fileCount = Math.max(0, Number(build.file_count) || 0);
  const channel = ({ dev: "Development", qa: "QA", live: "Live", deprecated: "Deprecated" })[build.channel] || build.channel || "Not assigned";
  const fields = [
    { name: "Project", value: `[${discordText(project.name, 200) || "Project"}](${projectUrl.toString()})`, inline: true },
    { name: "Channel", value: discordCode(channel, 100), inline: true },
    { name: "Package", value: build.file_count == null ? "No build uploaded yet" : `${fileCount} ${fileCount === 1 ? "file" : "files"} · ${sizeText}`, inline: true },
  ];
  for (const [key, name] of [["branch", "Branch"], ["commit_sha", "Commit"], ["tag", "Tag"]]) {
    if (build[key]) {
      const value = key === "commit_sha" ? String(build[key]).slice(0, 7) : build[key];
      fields.push({ name, value: discordCode(value), inline: true });
    }
  }
  const summary = discordReleaseSummary(build.changelog);
  const intro = test
    ? `🧪 **Test message** · ${build.id ? "Preview of the latest build. No new upload was created." : "Your future build reports will use this layout."}`
    : "A new build has been uploaded successfully.";
  return {
    username: "ManoBuild Reporter", allowed_mentions: { parse: [] },
    embeds: [{ title: `📦 Build report: ${String(build.version || "Preview").slice(0, 200)}`, url: url.toString(),
      description: intro + (summary ? `\n\n${summary}` : ""),
      color: 0x7c5cff, fields, timestamp: nowIso(),
      footer: { text: `GameDashboard · ${test ? "Test message" : "Upload complete"}` },
    }],
  };
}

async function deliverDiscordWebhook(env, projectId, webhookUrl, message) {
  let error = null;
  try {
    const url = new URL(normalizeDiscordWebhook(webhookUrl));
    // wait=true makes Discord confirm creation rather than silently accepting.
    url.searchParams.set("wait", "true");
    const response = await fetch(url.toString(), {
      method: "POST", headers: { "Content-Type": "application/json" },
      // Inspect redirects explicitly; the deployed Workers runtime rejects "error".
      body: JSON.stringify(message), redirect: "manual", signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) error = `Discord HTTP ${response.status}`;
    // Body cleanup must not turn Discord's confirmed response into a failure.
    try { await response.body?.cancel(); } catch {}
  } catch { error = "Discord could not be reached, timed out, or rejected the webhook URL."; }
  const now = nowIso();
  try {
    await env.DB.prepare("UPDATE project_discord_webhooks SET last_attempt_at = ?, last_sent_at = CASE WHEN ? IS NULL THEN ? ELSE last_sent_at END, last_error = ? WHERE project_id = ? AND webhook_url = ?")
      .bind(now, error, now, error, projectId, webhookUrl).run();
  } catch {
    console.warn(JSON.stringify({ event: "discord_webhook_status_failed", project_id: projectId }));
  }
  if (error) console.warn(JSON.stringify({ event: "discord_webhook_delivery_failed", project_id: projectId, error }));
  return { ok: !error, error };
}

async function notifyDiscordUpload(env, project, build, baseUrl) {
  try {
    const row = await env.DB.prepare("SELECT webhook_url, enabled, channels_json FROM project_discord_webhooks WHERE project_id = ?").bind(project.id).first();
    if (!row?.enabled || !row.webhook_url || !JSON.parse(row.channels_json).includes(build.channel)) return;
    await deliverDiscordWebhook(env, project.id, row.webhook_url, discordUploadMessage(project, build, baseUrl));
  } catch {
    // Notifications must never make a completed upload fail or reveal credentials.
    console.warn(JSON.stringify({ event: "discord_webhook_notification_failed", project_id: project.id, build_id: build.id }));
  }
}

async function testDiscordWebhook(env, project, baseUrl) {
  const row = await env.DB.prepare("SELECT webhook_url, channels_json FROM project_discord_webhooks WHERE project_id = ?").bind(project.id).first();
  if (!row?.webhook_url) return tokenJson({ error: "Save a webhook URL before sending a test message." }, 400);
  const latest = await env.DB.prepare("SELECT * FROM builds WHERE project_id = ? ORDER BY created_at DESC, id DESC LIMIT 1").bind(project.id).first();
  const preview = latest || { version: "Preview", channel: JSON.parse(row.channels_json)[0] || "dev" };
  const result = await deliverDiscordWebhook(env, project.id, row.webhook_url, discordUploadMessage(project, preview, baseUrl, { test: true }));
  return tokenJson(result.ok ? { ok: true } : { error: result.error }, result.ok ? 200 : 502);
}

function requireLogin(user, asJson = false) {
  if (user) return null;
  return asJson ? json({ error: "unauthorized" }, 401) : redirect("/login");
}

function requireRole(user, ...rolesAndMaybeJson) {
  const asJson = rolesAndMaybeJson[rolesAndMaybeJson.length - 1] === true;
  const roles = asJson ? rolesAndMaybeJson.slice(0, -1) : rolesAndMaybeJson;
  if (!user) return requireLogin(user, asJson);
  if (!roles.includes(user.role)) return asJson ? json({ error: "forbidden" }, 403) : redirect("/");
  return null;
}

async function login(request, env) {
  const session = await createSession(request, env);
  if (!session.ok) return loginPage(session.error);
  return redirect("/", { "Set-Cookie": session.cookie });
}

async function logout(request, env) {
  await clearSession(request, env);
  return redirect("/login", { "Set-Cookie": expiredSessionCookie() });
}

async function loginJson(request, env) {
  const session = await createSession(request, env);
  if (!session.ok) return json({ error: session.error }, 401);
  return json({ user: describeUser(session.user) }, 200, { "Set-Cookie": session.cookie });
}

async function logoutJson(request, env) {
  await clearSession(request, env);
  return json({ ok: true }, 200, { "Set-Cookie": expiredSessionCookie() });
}

async function dashboard(request, env, user) {
  const url = new URL(request.url);
  const projects = await listProjects(env, user);
  const selectedId = url.searchParams.get("project") || projects[0]?.id || null;
  const selected = selectedId ? await getProject(env, selectedId, user) : null;
  const builds = selected ? await listBuilds(env, selected.id, user, url.origin) : [];
  const users = user.role === "admin" ? await listUsers(env) : [];
  const view = url.searchParams.get("view") || "dashboard";
  const apiTokens = selected && view === "settings" && user.role === "admin" && user.auth_type === "session" ? await listProjectTokens(env, selected.id) : [];
  const discordWebhook = selected && view === "settings" && user.role === "admin" && user.auth_type === "session" ? await discordWebhookState(env, selected.id) : null;
  let bugReports = [];
  if (selected && ["logs", "report"].includes(view) && ["admin", "dev", "QA"].includes(user.role)) {
    if (view === "report") {
      const report = await env.DB.prepare("SELECT * FROM bug_reports WHERE id = ? AND project_id = ?")
        .bind(url.searchParams.get("report") || "", selected.id).first();
      if (report) bugReports = [report];
    } else bugReports = await listBugReports(env, selected.id);
  }
  const response = html(renderAdmin({ user, projects, selected, builds, users, bugReports, apiTokens, discordWebhook, view, reportId: url.searchParams.get("report"), buildId: url.searchParams.get("build") }, { createProjectForm, projectManagement, uploadPanel, userAccess, buildCard, apiTokenPanel, discordWebhookPanel, style }));
  response.headers.set("Cache-Control", "private, no-store");
  return response;
}

async function listProjects(env, user = null) {
  const { results } = await env.DB.prepare("SELECT * FROM projects ORDER BY created_at DESC").all();
  const projects = results || [];
  const visibleProjects = [];
  for (const project of projects) {
    if (!canAccessProject(user, project)) continue;
    if (!user) {
      const liveBuild = await env.DB.prepare(
        "SELECT 1 FROM builds WHERE project_id = ? AND channel = 'live' LIMIT 1"
      ).bind(project.id).first();
      if (!liveBuild) continue;
    }
    visibleProjects.push(projectToPayload(project));
  }
  return visibleProjects;
}

async function getProject(env, id, user = null) {
  const project = await env.DB.prepare("SELECT * FROM projects WHERE id = ?").bind(id).first();
  return canAccessProject(user, project) ? projectToPayload(project) : null;
}

async function listBuilds(env, projectId, user = null, baseUrl = "") {
  const project = await getProject(env, projectId, user);
  if (!project) return [];
  const { results } = await env.DB.prepare("SELECT * FROM builds WHERE project_id = ? ORDER BY created_at DESC").bind(projectId).all();
  const visibleChannels = new Set(visibleChannelsForRole(user?.role));
  return Promise.all((results || []).filter(row => visibleChannels.has(normalizeChannel(row.channel))).map(row => rowToBuild(env, row, baseUrl)));
}

async function createBugReport(request, env, user) {
  let payload;
  try {
    payload = await readLimitedJson(request, 16 * 1024 * 1024);
  } catch (error) {
    if (error instanceof RangeError) return json({ error: "report payload exceeds 16 MB" }, 413);
    return json({ error: "invalid JSON payload" }, 400);
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return json({ error: "invalid report payload" }, 400);
  const projectId = String(payload.project_id || "").trim();
  const buildId = String(payload.build_id || "").trim();
  const description = String(payload.description || "").trim();
  const sessionId = String(payload.session_id || "").trim().slice(0, 128);
  const unityVersion = String(payload.unity_version || "").trim().slice(0, 64);
  const sceneName = String(payload.scene_name || "").trim().slice(0, 200);
  const logs = typeof payload.logs === "string" ? payload.logs : "";

  if (!projectId || !buildId || description.length < 5 || description.length > 4000) {
    return json({ error: "project, build, and a 5-4000 character description are required" }, 400);
  }
  if (encoder.encode(logs).byteLength > 2 * 1024 * 1024) {
    return json({ error: "attached logs exceed the 2 MB limit" }, 413);
  }

  let snapshot;
  try { snapshot = decodeSnapshot(payload.snapshot); }
  catch (error) { return json({ error: error.message }, error instanceof RangeError ? 413 : 400); }
  const project = await getProject(env, projectId, user);
  if (!project) return json({ error: "project not found or access denied" }, 404);
  const build = await env.DB.prepare("SELECT id, version, channel FROM builds WHERE id = ? AND project_id = ?")
    .bind(buildId, projectId)
    .first();
  if (!build || !visibleChannelsForRole(user.role).includes(normalizeChannel(build.channel))) {
    return json({ error: "build not found or access denied" }, 404);
  }

  const now = nowIso();
  const reportId = `BUG-${new Date(now).toISOString().slice(0, 10).replaceAll("-", "")}-${crypto.randomUUID().replaceAll("-", "").slice(0, 8).toUpperCase()}`;
  const logObjectPath = logs
    ? `bug-reports/${safeObjectSegment(projectId)}/${reportId}/player.log`
    : null;
  const snapshotObjectPath = snapshot ? `bug-reports/${safeObjectSegment(projectId)}/${reportId}/snapshot.${snapshot.type === "image/png" ? "png" : "jpg"}` : null;
  if ((logObjectPath || snapshotObjectPath) && !env.BUILDS_BUCKET) return json({ error: "bug report storage is not configured" }, 503);

  const storedPaths = [];
  try {
    if (logObjectPath) {
      await env.BUILDS_BUCKET.put(logObjectPath, logs, {
        httpMetadata: { contentType: "text/plain; charset=utf-8" },
      });
      storedPaths.push(logObjectPath);
    }

    if (snapshotObjectPath) {
      await env.BUILDS_BUCKET.put(snapshotObjectPath, snapshot.bytes, { httpMetadata: { contentType: snapshot.type } });
      storedPaths.push(snapshotObjectPath);
    }
    await env.DB.prepare(
      "INSERT INTO bug_reports (id, project_id, build_id, version, reporter_email, description, unity_version, scene_name, session_id, status, log_object_path, log_size, snapshot_object_path, snapshot_size, snapshot_content_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      reportId,
      projectId,
      buildId,
      build.version,
      user.email,
      description,
      unityVersion,
      sceneName,
      sessionId,
      logObjectPath,
      encoder.encode(logs).byteLength,
      snapshotObjectPath,
      snapshot?.bytes.byteLength || 0,
      snapshot?.type || null,
      now,
      now,
    ).run();
  } catch (error) {
    if (storedPaths.length) {
      try {
        await env.BUILDS_BUCKET.delete(storedPaths);
      } catch {
        // Keep the original database/storage error as the one returned to the caller.
      }
    }
    throw error;
  }

  return json({ id: reportId, status: "new" }, 201);
}

async function readLimitedJson(request, maxBytes) {
  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (declaredLength > maxBytes) {
    await request.body?.cancel();
    throw new RangeError("request body too large");
  }

  const reader = request.body?.getReader();
  if (!reader) return {};
  const chunks = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new RangeError("request body too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function listBugReportsJson(request, env, user) {
  const url = new URL(request.url);
  const projectId = String(url.searchParams.get("project_id") || "").trim();
  if (!projectId) return json({ error: "project_id is required" }, 400);
  if (!await getProject(env, projectId, user)) return json({ error: "project not found or access denied" }, 404);
  return json(await listBugReports(env, projectId));
}

async function listBugReports(env, projectId) {
  const { results } = await env.DB.prepare(
    "SELECT id, project_id, build_id, version, reporter_email, description, unity_version, scene_name, session_id, status, log_object_path, log_size, snapshot_object_path, snapshot_size, snapshot_content_type, created_at, updated_at FROM bug_reports WHERE project_id = ? ORDER BY created_at DESC LIMIT 100"
  ).bind(projectId).all();
  return results || [];
}

async function downloadBugReportLog(env, user, reportId, preview = false) {
  const report = await env.DB.prepare("SELECT * FROM bug_reports WHERE id = ?").bind(reportId).first();
  if (!report || !report.log_object_path || !await getProject(env, report.project_id, user)) {
    return json({ error: "log not found" }, 404);
  }
  const object = await env.BUILDS_BUCKET.get(report.log_object_path);
  if (!object) return json({ error: "log file not found" }, 404);
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Cache-Control", "private, no-store");
  headers.set("Content-Type", "text/plain; charset=utf-8");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Content-Disposition", `${preview ? "inline" : "attachment"}; filename="${report.id}-player.log"`);
  return new Response(object.body, { headers });
}

async function downloadBugReportSnapshot(env, user, reportId) {
  const report = await env.DB.prepare("SELECT * FROM bug_reports WHERE id = ?").bind(reportId).first();
  if (!report?.snapshot_object_path || !await getProject(env, report.project_id, user)) return json({ error: "snapshot not found" }, 404);
  const object = await env.BUILDS_BUCKET.get(report.snapshot_object_path);
  if (!object) return json({ error: "snapshot file not found" }, 404);
  return new Response(object.body, { headers: {
    "Content-Type": report.snapshot_content_type === "image/png" ? "image/png" : "image/jpeg",
    "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff",
    "Content-Disposition": "inline", "ETag": object.httpEtag,
  } });
}

function decodeSnapshot(value) {
  if (value == null || value === "") return null;
  if (typeof value !== "string") throw new Error("snapshot must be a PNG or JPEG base64 data URL");
  const match = /^data:(image\/(?:png|jpeg));base64,([A-Za-z0-9+/]*={0,2})$/.exec(value);
  if (!match || match[2].length % 4 !== 0) throw new Error("invalid snapshot data URL");
  if (match[2].length > Math.ceil(2 * 1024 * 1024 / 3) * 4) throw new RangeError("snapshot exceeds the 2 MB limit");
  const bytes = Uint8Array.from(atob(match[2]), character => character.charCodeAt(0));
  if (bytes.byteLength > 2 * 1024 * 1024) throw new RangeError("snapshot exceeds the 2 MB limit");
  const png = [137, 80, 78, 71, 13, 10, 26, 10].every((byte, index) => bytes[index] === byte);
  const jpeg = bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255;
  if (!(match[1] === "image/png" ? png : jpeg)) throw new Error("snapshot content does not match its image type");
  return { bytes, type: match[1] };
}

async function updateBugReportStatus(request, env, user, reportId) {
  const report = await env.DB.prepare("SELECT project_id FROM bug_reports WHERE id = ?").bind(reportId).first();
  if (!report || !await getProject(env, report.project_id, user)) return json({ error: "bug report not found" }, 404);
  const form = await request.formData();
  const status = String(form.get("status") || "").trim();
  if (!["new", "triaged", "resolved", "closed"].includes(status)) return json({ error: "invalid status" }, 400);
  await env.DB.prepare("UPDATE bug_reports SET status = ?, updated_at = ? WHERE id = ?")
    .bind(status, nowIso(), reportId)
    .run();
  return redirect(`/?view=${form.get("return_to") === "report" ? "report" : "logs"}&project=${encodeURIComponent(report.project_id)}${form.get("return_to") === "report" ? "&report=" + encodeURIComponent(reportId) : ""}`);
}

function safeObjectSegment(value) {
  return String(value || "").replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^\.+|\.+$/g, "") || "project";
}

async function launcherLibrary(env, user) {
  const projects = await listProjects(env, user);
  const allowed = new Set(projects.map(project => project.id));
  const channels = new Set(visibleChannelsForRole(user.role));
  const { results } = await env.DB.prepare("SELECT * FROM builds ORDER BY created_at DESC").all();
  const buildsByProject = new Map(projects.map(project => [project.id, []]));
  for (const row of results || []) {
    if (!allowed.has(row.project_id) || !channels.has(normalizeChannel(row.channel))) continue;
    buildsByProject.get(row.project_id).push(rowToLauncherSummary(row));
  }
  return projects.map(project => ({ ...project, builds: buildsByProject.get(project.id) }));
}

function rowToLauncherSummary(row) {
  const manifest = row.manifest_json ? JSON.parse(row.manifest_json) : {};
  return {
    id: row.id,
    version: row.version,
    channel: normalizeChannel(row.channel),
    status: row.status,
    build_code: row.build_code,
    platform: row.platform,
    branch: row.branch,
    commit: row.commit_sha,
    date: row.created_at,
    size: Number(row.total_size || manifest.total_size || 0),
    changelog: row.changelog,
    test_instructions: row.test_instructions,
    qa_notes: row.qa_notes,
    focus_areas: row.focus_areas,
    known_issues: row.known_issues,
    manifest: {
      files: (manifest.files || []).map(file => ({ path: file.path, hash: file.hash, size: file.size })),
    },
  };
}

async function listUsers(env) {
  const { results } = await env.DB.prepare("SELECT email, role, created_at, updated_at FROM users ORDER BY email").all();
  return results || [];
}

async function createProject(request, env) {
  const form = await request.formData();
  const id = `project-${crypto.randomUUID().slice(0, 8)}`;
  const now = nowIso();
  const metadata = projectMetadataFromForm(form, {});
  await env.DB.prepare(
    "INSERT INTO projects (id, name, icon, bundle_id, role, banner_title, banner_subtitle, description, cover_url, known_issues, test_instructions, focus_areas, maintenance_notice, save_path_hint, config_path_hint, recommended_profile, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    id,
    field(form, "name"),
    field(form, "icon") || "GM",
    field(form, "bundle_id"),
    field(form, "role") || "viewer",
    metadata.banner_title,
    metadata.banner_subtitle,
    metadata.description,
    metadata.cover_url,
    metadata.known_issues,
    metadata.test_instructions,
    metadata.focus_areas,
    metadata.maintenance_notice,
    metadata.save_path_hint,
    metadata.config_path_hint,
    metadata.recommended_profile,
    now,
    now
  ).run();
  return redirect(`/?project=${id}`);
}

async function updateProject(request, env, id) {
  const form = await request.formData();
  const existing = await env.DB.prepare("SELECT * FROM projects WHERE id = ?").bind(id).first();
  const metadata = projectMetadataFromForm(form, existing || {});
  await env.DB.prepare("UPDATE projects SET name = ?, icon = ?, bundle_id = ?, role = ?, banner_title = ?, banner_subtitle = ?, description = ?, cover_url = ?, known_issues = ?, test_instructions = ?, focus_areas = ?, maintenance_notice = ?, save_path_hint = ?, config_path_hint = ?, recommended_profile = ?, updated_at = ? WHERE id = ?")
    .bind(
      field(form, "name"),
      field(form, "icon") || "GM",
      field(form, "bundle_id"),
      field(form, "role") || "viewer",
      metadata.banner_title,
      metadata.banner_subtitle,
      metadata.description,
      metadata.cover_url,
      metadata.known_issues,
      metadata.test_instructions,
      metadata.focus_areas,
      metadata.maintenance_notice,
      metadata.save_path_hint,
      metadata.config_path_hint,
      metadata.recommended_profile,
      nowIso(),
      id
    )
    .run();
  return redirect(`/?project=${id}`);
}

async function deleteProject(request, env, id) {
  await deleteProjectData(env, id);
  return redirect("/");
}

async function deleteProjectJson(env, id) {
  const deletedBuilds = await deleteProjectData(env, id);
  return json({ id, deleted_builds: deletedBuilds });
}

async function deleteProjectData(env, id) {
  const builds = await listBuilds(env, id, { role: "admin" });
  const listed = await env.BUILDS_BUCKET.list({ prefix: `builds/${id}/` });
  await Promise.all((listed.objects || []).map(object => env.BUILDS_BUCKET.delete(object.key)));
  await env.DB.prepare("DELETE FROM builds WHERE project_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM project_api_tokens WHERE project_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM project_discord_webhooks WHERE project_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM upload_queue WHERE project_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM build_upload_versions WHERE project_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(id).run();
  return builds.length;
}

async function upsertUser(request, env) {
  const form = await request.formData();
  const email = field(form, "email").toLowerCase();
  const role = USER_ROLES.includes(field(form, "role")) ? field(form, "role") : "viewer";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return redirect("/?view=settings");
  const existing = await env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(email).first();
  const now = nowIso();
  if (existing) {
    await env.DB.prepare("UPDATE users SET role = ?, updated_at = ? WHERE email = ?").bind(role, now, email).run();
  } else {
    await env.DB.prepare(
      "INSERT INTO users (email, role, password_hash, created_at, updated_at) VALUES (?, ?, '', ?, ?)"
    ).bind(email, role, now, now).run();
  }
  return redirect("/?view=settings");
}

async function updateUserRole(request, env, current, email) {
  const form = await request.formData();
  const role = USER_ROLES.includes(field(form, "role")) ? field(form, "role") : "viewer";
  if (email === current.email && role !== "admin") return redirect("/");
  await env.DB.prepare("UPDATE users SET role = ?, updated_at = ? WHERE email = ?").bind(role, nowIso(), email).run();
  return redirect("/");
}

async function deleteUser(request, env, current, email) {
  if (email === current.email) return redirect("/");
  await env.DB.prepare("DELETE FROM sessions WHERE email = ?").bind(email).run();
  await env.DB.prepare("DELETE FROM users WHERE email = ?").bind(email).run();
  return redirect("/");
}

async function initUploadSession(request, env, user, projectId) {
  const denied = uploadMutationGuard(request, user);
  if (denied) return denied;
  const missing = ["R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET_NAME"].filter(key => !env[key]);
  if (missing.length) return json({ error: `missing R2 config: ${missing.join(", ")}` }, 500);

  const payload = await request.json();
  const channel = String(payload.channel || "dev").trim().toLowerCase();
  if (!CHANNELS.includes(channel)) return json({ error: "invalid channel" }, 400);
  if (!canAssign(user, channel)) return json({ error: "forbidden" }, 403);
  const project = await getProject(env, projectId, user);
  if (!project) return json({ error: "project not found" }, 404);
  const files = Array.isArray(payload.files) ? payload.files.map(file => ({ ...file, size: payload.queue === true ? file?.size : Number(file?.size || 0) })) : payload.files;
  if (!Array.isArray(files) || !files.length || files.length > 100 || files.some(file => !file || typeof file.name !== "string" || !file.name || file.name.length > 512 || !Number.isSafeInteger(file.size) || file.size < 0)) return json({ error: "Provide 1–100 files with names and valid sizes." }, 400);
  if (!Number.isSafeInteger(files.reduce((sum, file) => sum + file.size, 0))) return json({ error: "Invalid total file size." }, 400);
  if (payload.queue === true && Number((await env.DB.prepare("SELECT COUNT(*) AS count FROM upload_queue WHERE project_id = ? AND status = 'waiting'").bind(projectId).first()).count) >= 200) return tokenJson({ error: "This project's upload queue is full. Try again later." }, 429);
  const buildId = `build-${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
  const version = await nextVersion(env, projectId, project.icon);
  await env.DB.prepare("INSERT INTO build_upload_versions (build_id, project_id, version, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(buildId, projectId, version, user.email, nowIso()).run();
  const queued = payload.queue === true;
  const now = nowIso();
  const descriptors = files.map(file => ({ name: file.name, size: file.size, content_type: String(file.content_type || "application/octet-stream").slice(0, 200) }));
  await env.DB.prepare(`INSERT INTO upload_queue (build_id,project_id,version,owner,channel,source,branch,files_json,total_bytes,managed,status,phase,sort_order,created_at,updated_at,lease_expires_at)
    SELECT ?,?,?,?,?,?,?,?,?,?,?,?,COALESCE(MAX(sort_order),0)+1024,?,?,? FROM upload_queue WHERE project_id = ?`)
    .bind(buildId, projectId, version, user.email, channel, String(payload.build_source || "Dashboard").slice(0,100), String(payload.branch || "").slice(0,200), JSON.stringify(descriptors), descriptors.reduce((sum, file) => sum + file.size, 0), queued ? 1 : 0, queued ? "waiting" : "legacy", queued ? "waiting" : "uploading", now, now, uploadLease(queued ? 300 : 1800), projectId).run();
  if (queued) {
    await advanceUploadQueue(env, projectId);
    const job = await env.DB.prepare("SELECT * FROM upload_queue WHERE build_id = ?").bind(buildId).first();
    return tokenJson(await uploadSessionResponse(env, job), job.status === "waiting" ? 202 : 200);
  }
  const uploads = [];
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    const contentType = file.content_type || "application/octet-stream";
    const objectPath = objectPathFor(projectId, buildId, file.name, index + 1);
    uploads.push({
      name: file.name || "",
      size: Number(file.size || 0),
      content_type: contentType,
      object_path: objectPath,
      upload_url: await presignPut(env, objectPath, contentType),
    });
  }
  return json({ build_id: buildId, version, bucket: env.R2_BUCKET_NAME, expires_in_seconds: 1800, uploads });
}

async function completeUploadSession(request, env, user, projectId, buildId, ctx) {
  const denied = uploadMutationGuard(request, user);
  if (denied) return denied;
  const baseUrl = new URL(request.url).origin;
  const project = await getProject(env, projectId, user);
  if (!project) return json({ error: "project not found" }, 404);
  const reservation = await env.DB.prepare("SELECT * FROM build_upload_versions WHERE build_id = ? AND project_id = ? AND uploaded_by = ?")
    .bind(buildId, projectId, user.email).first();
  if (!reservation) return json({ error: "Upload session not found. Initialize a new upload." }, 400);
  if (await env.DB.prepare("SELECT id FROM builds WHERE id = ?").bind(buildId).first()) {
    return json({ error: "Build already completed" }, 409);
  }
  const payload = await request.json();
  // The version reserved by the server is authoritative, even for older clients.
  payload.version = reservation.version;
  const channel = String(payload.channel || "dev").trim().toLowerCase();
  if (!CHANNELS.includes(channel)) return json({ error: "invalid channel" }, 400);
  if (!canAssign(user, channel)) return json({ error: "forbidden" }, 403);
  const files = payload.files || [];
  if (!Array.isArray(files) || !files.length) return json({ error: "files are required" }, 400);
  if (user.auth_type === "project-token" && files.some((file, index) => file.object_path !== objectPathFor(projectId, buildId, file.name, index + 1))) {
    return json({ error: "Files must belong to this project's upload session." }, 400);
  }
  const job = await env.DB.prepare("SELECT * FROM upload_queue WHERE build_id = ? AND project_id = ?").bind(buildId, projectId).first();
  if (job?.managed) {
    const expected = JSON.parse(job.files_json);
    if (job.channel !== channel || files.length !== expected.length || files.some((file, index) => file.name !== expected[index].name || file.size !== expected[index].size || file.object_path !== objectPathFor(projectId, buildId, file.name, index + 1))) {
      return tokenJson({ error: "Files and channel must match the queued upload." }, 400);
    }
    const claimed = await env.DB.prepare("UPDATE upload_queue SET status = 'finalizing', phase = 'finalizing', updated_at = ?, lease_expires_at = ? WHERE build_id = ? AND status = 'uploading' AND lease_expires_at > ? RETURNING build_id")
      .bind(nowIso(), uploadLease(), buildId, nowIso()).first();
    if (!claimed) return tokenJson({ error: "This upload is not active. Initialize a new upload if its lease expired." }, 409);
  }
  const manifestFiles = await Promise.all(files.map(async file => {
    const downloadUrl = await objectDownloadUrl(env, file.object_path, baseUrl);
    return {
      path: file.name || "build.bin",
      hash: file.hash || "",
      size: Number(file.size || 0),
      content_type: file.content_type || "application/octet-stream",
      storage_object: file.object_path,
      storage_url: downloadUrl,
      download_url: downloadUrl,
    };
  }));
  const manifest = {
    generated_at: nowIso(),
    source: "cloudflare-r2-upload",
    file_count: files.length,
    total_size: files.reduce((sum, file) => sum + Number(file.size || 0), 0),
    files: manifestFiles,
  };
  let build;
  try { build = await saveBuild(env, projectId, buildId, payload, manifest, baseUrl, user); }
  catch (error) {
    await env.DB.prepare("UPDATE upload_queue SET status = 'failed', phase = 'failed', updated_at = ? WHERE build_id = ? AND status = 'finalizing'").bind(nowIso(), buildId).run();
    await advanceUploadQueue(env, projectId);
    throw error;
  }
  await env.DB.prepare("UPDATE upload_queue SET status = 'completed', phase = 'completed', uploaded_bytes = total_bytes, updated_at = ? WHERE build_id = ?").bind(nowIso(), buildId).run();
  await env.DB.prepare("DELETE FROM build_upload_versions WHERE build_id = ?").bind(buildId).run();
  await advanceUploadQueue(env, projectId);
  const notification = notifyDiscordUpload(env, project, build, baseUrl);
  if (ctx?.waitUntil) ctx.waitUntil(notification);
  else await notification;
  return json(build, 201);
}

function uploadMutationGuard(request, user) {
  if (request.method === "GET") return null;
  if (user?.auth_type === "session" && request.headers.get("Origin") !== new URL(request.url).origin) return tokenJson({ error: "Invalid request origin." }, 403);
  if (user?.auth_type === "session" && !(request.headers.get("Content-Type") || "").toLowerCase().startsWith("application/json")) return tokenJson({ error: "Use application/json." }, 415);
  return null;
}

function uploadLease(seconds = 300) { return new Date(Date.now() + seconds * 1000).toISOString(); }

// A single conditional SQL write claims the first waiting build. The partial
// unique index also prevents two active uploads for the same project.
async function advanceUploadQueue(env, projectId) {
  const now = nowIso();
  await env.DB.prepare("UPDATE upload_queue SET status = 'expired', phase = 'expired', updated_at = ? WHERE project_id = ? AND status IN ('waiting','uploading','finalizing','legacy') AND lease_expires_at <= ?")
    .bind(now, projectId, now).run();
  await env.DB.prepare(`UPDATE upload_queue SET status = 'uploading', phase = 'preparing', started_at = ?, updated_at = ?, lease_expires_at = ?
    WHERE build_id = (SELECT build_id FROM upload_queue WHERE project_id = ? AND status = 'waiting' ORDER BY sort_order, created_at, build_id LIMIT 1)
    AND status = 'waiting' AND NOT EXISTS (SELECT 1 FROM upload_queue WHERE project_id = ? AND status IN ('uploading','finalizing','legacy'))`)
    .bind(now, now, uploadLease(), projectId, projectId).run();
}

async function uploadSessionResponse(env, job, includeUrls = true) {
  const position = job.status === "waiting" ? Number((await env.DB.prepare(`SELECT COUNT(*) AS count FROM upload_queue WHERE project_id = ? AND status = 'waiting'
    AND (sort_order < ? OR (sort_order = ? AND (created_at < ? OR (created_at = ? AND build_id <= ?))))`)
    .bind(job.project_id, job.sort_order, job.sort_order, job.created_at, job.created_at, job.build_id).first()).count) : 0;
  const result = { build_id: job.build_id, version: job.version, status: job.status, phase: job.phase, position, uploaded_bytes: job.uploaded_bytes, total_bytes: job.total_bytes, lease_expires_at: job.lease_expires_at, poll_after_seconds: 3 };
  if (job.status === "uploading" && includeUrls) {
    result.bucket = env.R2_BUCKET_NAME;
    result.expires_in_seconds = 1800;
    result.uploads = await Promise.all(JSON.parse(job.files_json).map(async (file, index) => {
      const object_path = objectPathFor(job.project_id, job.build_id, file.name, index + 1);
      return { ...file, object_path, upload_url: await presignPut(env, object_path, file.content_type) };
    }));
  }
  return result;
}

async function updateUploadSession(request, env, user, projectId, buildId, action) {
  if (request.method !== (action === "status" ? "GET" : "POST")) return tokenJson({ error: "method not allowed" }, 405);
  if (!await getProject(env, projectId, user)) return tokenJson({ error: "project not found" }, 404);
  let job = await env.DB.prepare("SELECT * FROM upload_queue WHERE build_id = ? AND project_id = ? AND owner = ?").bind(buildId, projectId, user.email).first();
  if (!job) return tokenJson({ error: "Upload session not found." }, 404);
  const now = nowIso();
  if (action === "fail") {
    await env.DB.prepare("UPDATE upload_queue SET status = 'failed', phase = 'failed', updated_at = ? WHERE build_id = ? AND status IN ('waiting','uploading','legacy')").bind(now, buildId).run();
  } else if (action === "status") {
    await env.DB.prepare("UPDATE upload_queue SET lease_expires_at = ? WHERE build_id = ? AND status IN ('waiting','uploading') AND lease_expires_at > ?").bind(uploadLease(), buildId, now).run();
  } else {
    let payload;
    try { payload = await readLimitedJson(request, 4096); } catch { return tokenJson({ error: "Invalid progress." }, 400); }
    const bytes = payload?.uploaded_bytes;
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > job.total_bytes || !['preparing','hashing','uploading','finalizing'].includes(payload.phase)) return tokenJson({ error: "Invalid progress." }, 400);
    await env.DB.prepare("UPDATE upload_queue SET uploaded_bytes = MAX(uploaded_bytes, ?), phase = ?, updated_at = ?, lease_expires_at = ? WHERE build_id = ? AND status = 'uploading' AND lease_expires_at > ?")
      .bind(bytes, payload.phase, now, uploadLease(), buildId, now).run();
  }
  await advanceUploadQueue(env, projectId);
  job = await env.DB.prepare("SELECT * FROM upload_queue WHERE build_id = ?").bind(buildId).first();
  return tokenJson(await uploadSessionResponse(env, job, action === "status"));
}

async function listUploadQueue(env, projectId) {
  await advanceUploadQueue(env, projectId);
  const { results } = await env.DB.prepare(`SELECT build_id, version, channel, source, branch, files_json, total_bytes, uploaded_bytes, status, phase, created_at, updated_at, started_at
    FROM upload_queue WHERE project_id = ? AND status IN ('waiting','uploading','finalizing','legacy') ORDER BY CASE WHEN status = 'waiting' THEN 1 ELSE 0 END, sort_order, created_at, build_id`).bind(projectId).all();
  let position = 0;
  return { jobs: (results || []).map(({ files_json, ...job }) => ({ ...job, position: job.status === "waiting" ? ++position : 0, files: JSON.parse(files_json).map(file => file.name) })), refreshed_at: nowIso() };
}

async function reorderUploadQueue(request, env, user, projectId) {
  if (user.auth_type !== "session") return tokenJson({ error: "Sign in to arrange the upload queue." }, 403);
  const denied = uploadMutationGuard(request, user);
  if (denied) return denied;
  let payload;
  try { payload = await readLimitedJson(request, 32_768); } catch { return tokenJson({ error: "Invalid queue order." }, 400); }
  const ids = payload?.build_ids;
  if (!Array.isArray(ids) || !ids.length || ids.length > 200 || ids.some(id => typeof id !== 'string') || new Set(ids).size !== ids.length) return tokenJson({ error: "Provide the waiting build IDs in order (up to 200)." }, 400);
  // Verify the snapshot and apply every position in the same statement. A job
  // admitted or inserted concurrently makes this a conflict, never a lost order.
  const order = JSON.stringify(ids);
  const changed = await env.DB.prepare(`UPDATE upload_queue SET sort_order = (SELECT (CAST(key AS INTEGER)+1)*1024 FROM json_each(?) WHERE value = build_id), updated_at = ?
    WHERE project_id = ? AND status = 'waiting'
    AND (SELECT COUNT(*) FROM upload_queue WHERE project_id = ? AND status = 'waiting') = ?
    AND NOT EXISTS (SELECT 1 FROM json_each(?) desired WHERE NOT EXISTS (SELECT 1 FROM upload_queue actual WHERE actual.build_id = desired.value AND actual.project_id = ? AND actual.status = 'waiting')) RETURNING build_id`)
    .bind(order, nowIso(), projectId, projectId, ids.length, order, projectId).all();
  if (changed.results.length !== ids.length) return tokenJson({ error: "The queue changed. Refresh and try again." }, 409);
  return tokenJson(await listUploadQueue(env, projectId));
}

async function saveBuild(env, projectId, buildId, payload, manifest, baseUrl = "", user = null) {
  const now = nowIso();
  const version = payload.version;
  const channel = String(payload.channel || "dev").trim().toLowerCase();
  const manifestJson = JSON.stringify(manifest);
  const manifestId = stringField(payload, "manifest_id") || await sha256Hex(manifestJson);
  const uploadedAt = stringField(payload, "uploaded_at") || now;
  const uploadedBy = stringField(payload, "uploaded_by") || user?.email || "";
  await env.DB.prepare(
    "INSERT INTO builds (id, project_id, version, channel, tag, changelog, status, commit_sha, uploaded_by, uploaded_at, manifest_id, checksum, branch, build_source, known_issues, test_instructions, focus_areas, save_path_hint, config_path_hint, file_count, total_size, storage_path, manifest_path, manifest_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'assigned', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    buildId,
    projectId,
    version,
    channel,
    stringField(payload, "tag"),
    stringField(payload, "changelog") || "Manual upload",
    stringField(payload, "commit_sha"),
    uploadedBy,
    uploadedAt,
    manifestId,
    stringField(payload, "checksum") || manifestId,
    stringField(payload, "branch"),
    stringField(payload, "build_source"),
    metadataText(payload, "known_issues"),
    metadataText(payload, "test_instructions"),
    metadataText(payload, "focus_areas"),
    stringField(payload, "save_path_hint"),
    stringField(payload, "config_path_hint"),
    manifest.file_count,
    manifest.total_size,
    `r2://${env.R2_BUCKET_NAME}/builds/${projectId}/${buildId}/files`,
    `r2://${env.R2_BUCKET_NAME}/builds/${projectId}/${buildId}/manifest.json`,
    manifestJson,
    now,
    now
  ).run();
  return rowToBuild(env, await env.DB.prepare("SELECT * FROM builds WHERE id = ?").bind(buildId).first(), baseUrl);
}

async function updateBuildChannel(request, env, user, buildId) {
  const payload = request.headers.get("content-type")?.includes("application/json")
    ? await request.json()
    : Object.fromEntries(await request.formData());
  const channel = String(payload.channel || "dev").trim().toLowerCase();
  if (!CHANNELS.includes(channel)) return json({ error: "invalid channel" }, 400);
  if (!canAssign(user, channel)) return json({ error: "forbidden" }, 403);
  await env.DB.prepare("UPDATE builds SET channel = ?, status = 'assigned', updated_at = ? WHERE id = ?").bind(channel, nowIso(), buildId).run();
  const build = await env.DB.prepare("SELECT project_id FROM builds WHERE id = ?").bind(buildId).first();
  return request.url.includes("/api/") ? json({ id: buildId, channel }) : redirect(`/?project=${build?.project_id || ""}`);
}

async function updateBuildDetails(request, env, user, buildId) {
  if (user.auth_type === "session" && request.headers.get("Origin") !== new URL(request.url).origin) {
    return json({ error: "Invalid request origin." }, 403);
  }
  if (!(request.headers.get("Content-Type") || "").toLowerCase().startsWith("application/json")) return json({ error: "Use application/json." }, 415);
  const build = await env.DB.prepare("SELECT * FROM builds WHERE id = ?").bind(buildId).first();
  if (!build || !await getProject(env, build.project_id, user)) return json({ error: "build not found" }, 404);
  let payload;
  try { payload = await readLimitedJson(request, 128 * 1024); }
  catch (error) { return json({ error: error instanceof RangeError ? "Build details are too large." : "Invalid JSON." }, 400); }
  const fields = ["tag", "changelog", "focus_areas", "test_instructions", "known_issues", "save_path_hint", "config_path_hint"];
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || !Object.keys(payload).length || Object.keys(payload).some(key => !fields.includes(key))) {
    return json({ error: "Only release notes, tag, and testing details can be edited here." }, 400);
  }
  const details = Object.fromEntries(fields.map(key => [key, build[key] || ""]));
  for (const key of fields) {
    if (!Object.hasOwn(payload, key)) continue;
    const value = payload[key];
    const list = key === "focus_areas" || key === "known_issues";
    if (typeof value !== "string" && !(list && Array.isArray(value) && value.every(item => typeof item === "string"))) {
      return json({ error: `${key} must be text${list ? " or a list of text items" : ""}.` }, 400);
    }
    const text = list ? JSON.stringify(parseMetadataList(value)) : value.trim();
    const max = key === "tag" ? 200 : key.endsWith("_hint") ? 1024 : key === "changelog" ? 64000 : 16000;
    if (text.length > max) return json({ error: `${key} exceeds ${max} characters.` }, 400);
    details[key] = text;
  }
  // Keep structured release notes and Launcher testing metadata consistent.
  // Older uploads may have stored Test Focus only inside the changelog.
  for (const [key, title] of [["focus_areas", "Test Focus"], ["known_issues", "Known Issues"]]) {
    if (Object.hasOwn(payload, key)) details.changelog = setReleaseSection(details.changelog, title, parseMetadataList(details[key]));
    else if (Object.hasOwn(payload, "changelog") && releaseSectionRanges(details.changelog, title).length) {
      details[key] = JSON.stringify(parseMetadataList(releaseSectionText(details.changelog, title)));
    }
  }
  if (details.changelog.length > 64000) return json({ error: "Combined release notes exceed 64000 characters." }, 400);
  const updatedAt = nowIso();
  const updated = await env.DB.prepare(
    "UPDATE builds SET tag = ?, changelog = ?, focus_areas = ?, test_instructions = ?, known_issues = ?, save_path_hint = ?, config_path_hint = ?, updated_at = ? WHERE id = ? RETURNING id, project_id"
  ).bind(...fields.map(key => details[key]), updatedAt, buildId).first();
  if (!updated) return json({ error: "build not found" }, 404);
  return json({ ...updated, ...details, focus_areas: parseMetadataList(details.focus_areas), known_issues: parseMetadataList(details.known_issues), updated_at: updatedAt }, 200, { "Cache-Control": "private, no-store" });
}

function releaseSectionRanges(value, title) {
  const lines = String(value || "").split(/\r?\n/);
  const ranges = [];
  let active = null;
  let fence = null;
  lines.forEach((line, index) => {
    const marker = line.trim().match(/^(`{3,}|~{3,})/);
    if (marker) { if (!fence) fence = marker[1][0]; else if (marker[1][0] === fence) fence = null; return; }
    if (fence) return;
    const heading = line.match(/^(#{1,6})\s+(.+?)\s*#*\s*$/);
    if (!heading) return;
    const level = heading[1].length;
    if (active && level <= active.level) { ranges.push({ start: active.start, end: index }); active = null; }
    if (!active && heading[2].trim().toLowerCase() === title.toLowerCase()) active = { start: index, level };
  });
  if (active) ranges.push({ start: active.start, end: lines.length });
  return ranges;
}

function releaseSectionText(value, title) {
  const range = releaseSectionRanges(value, title)[0];
  return range ? String(value).split(/\r?\n/).slice(range.start + 1, range.end).join("\n").trim() : "";
}

function setReleaseSection(value, title, items) {
  const lines = String(value || "").split(/\r?\n/);
  const ranges = releaseSectionRanges(value, title);
  const block = items.length ? [`## ${title}`, ...items.map(item => `- ${item}`), ""] : [];
  if (ranges.length) {
    [...ranges].reverse().forEach((range, index) => lines.splice(range.start, range.end - range.start, ...(index === ranges.length - 1 ? block : [])));
  } else if (block.length) {
    if (title === "Test Focus") lines.unshift(...block);
    else lines.push("", ...block);
  }
  return lines.join("\n").trim();
}

async function rollbackBuild(env, buildId) {
  const build = await env.DB.prepare("SELECT project_id FROM builds WHERE id = ?").bind(buildId).first();
  await env.DB.prepare("UPDATE builds SET channel = 'live', tag = 'rollback', updated_at = ? WHERE id = ?").bind(nowIso(), buildId).run();
  return redirect(`/?project=${build?.project_id || ""}`);
}

async function deleteBuild(env, buildId) {
  const result = await deleteBuildData(env, buildId);
  return redirect(`/?project=${result.project_id || ""}`);
}

async function deleteBuildJson(env, buildId) {
  const result = await deleteBuildData(env, buildId);
  return json({ id: buildId, project_id: result.project_id, deleted_files: result.deleted_files });
}

async function deleteBuildData(env, buildId) {
  const build = await env.DB.prepare("SELECT id, project_id FROM builds WHERE id = ?").bind(buildId).first();
  if (!build) return { project_id: "", deleted_files: 0 };
  const prefix = `builds/${build.project_id}/${build.id}/`;
  const listed = await env.BUILDS_BUCKET.list({ prefix });
  await Promise.all((listed.objects || []).map(object => env.BUILDS_BUCKET.delete(object.key)));
  await env.DB.prepare("DELETE FROM builds WHERE id = ?").bind(build.id).run();
  return { project_id: build.project_id, deleted_files: (listed.objects || []).length };
}

async function buildManifest(request, env, buildId, user = null) {
  const build = await env.DB.prepare("SELECT manifest_json, project_id, channel FROM builds WHERE id = ?").bind(buildId).first();
  if (!build) return json({ error: "build not found" }, 404);
  const project = await getProject(env, build.project_id, user);
  if (!project || !visibleChannelsForRole(user?.role).includes(normalizeChannel(build.channel))) return json({ error: "build not found" }, 404);
  return json(await manifestWithDownloadUrls(env, JSON.parse(build.manifest_json), new URL(request.url).origin));
}

async function launcherLatest(request, env) {
  const url = new URL(request.url);
  const channel = normalizeChannel(url.searchParams.get("channel"), "live");
  const currentVersion = String(url.searchParams.get("current_version") || "").trim();
  if (!hubR2Credentials(env)) {
    return json({ error: "launcher update storage is not configured" }, 503);
  }
  const hubRelease = await readHubLauncherMetadata(env, env.LAUNCHER_LATEST_KEY || "launcher/latest.json");
  if (!hubRelease) return json({ error: "launcher release not found", channel }, 404);
  const latest = await launcherLatestFromHub(env, currentVersion, channel, hubRelease);
  if (!latest) return json({ error: "launcher release artifacts not found", channel }, 404);
  return json(latest);
}

async function launcherLatestFromHub(env, currentVersion, channel, hubRelease) {
  const metadata = hubRelease.metadata;
  const downloadCredentials = hubRelease.credentials;
  const version = String(metadata.version || metadata.latest_version || "").trim();
  if (!version) return null;
  const hubToolSlug = hubLauncherToolSlug(metadata);
  if (!hubToolSlug) return null;

  const hasUpdate = currentVersion ? compareVersions(version, currentVersion) > 0 : true;
  const fullKey = String(metadata.full_key || "").trim();
  const installerKey = String(metadata.installer_key || "").trim();
  const useInstaller = isHubLauncherArtifactKey(installerKey, version, `ManoLauncher-Setup-${version}.exe`, hubToolSlug);
  const useFullArchive = isHubLauncherArtifactKey(fullKey, version, `ManoLauncher-${version}.zip`, hubToolSlug);
  if (!useInstaller && !useFullArchive) return null;
  const patchUrl = "";
  // The full ZIP can replace the packaged app directly after it exits. Keep
  // the installer endpoint for fresh installs and older release manifests.
  const artifactKey = useFullArchive ? fullKey : installerKey;
  const fullUrl = await presignGet(env, artifactKey, downloadCredentials);

  return {
    has_update: hasUpdate,
    is_mandatory: Boolean(metadata.is_mandatory),
    version,
    from_version: metadata.patch_from_version || metadata.from_version || "",
    patch_url: patchUrl,
    full_url: fullUrl,
    download_url: hasUpdate ? fullUrl : "",
    notes: metadata.notes || metadata.changelog || "No release notes.",
    channel,
    source: "mano_tools_hub_r2",
    release: {
      version,
      is_mandatory: Boolean(metadata.is_mandatory),
      notes: metadata.notes || metadata.changelog || "No release notes.",
      full_url: fullUrl,
      full_hash: useFullArchive ? (metadata.full_hash || metadata.hash || "") : (metadata.installer_hash || ""),
      full_size: useFullArchive ? Number(metadata.full_size || metadata.size || 0) : Number(metadata.installer_size || 0),
      patches: patchUrl
        ? [{
            from_version: metadata.patch_from_version || metadata.from_version || "",
            to_version: version,
            patch_url: patchUrl,
            hash: metadata.patch_hash || "",
            size: Number(metadata.patch_size || 0),
          }]
        : [],
    },
  };
}

async function launcherInstaller(env) {
  const key = env.LAUNCHER_LATEST_KEY || "launcher/latest.json";
  if (!hubR2Credentials(env)) {
    return json({ error: "launcher update storage is not configured" }, 503);
  }
  const hubRelease = await readHubLauncherMetadata(env, key);
  if (!hubRelease) return json({ error: "launcher release not found" }, 404);
  const version = String(hubRelease.metadata.version || "").trim();
  const installerKey = String(hubRelease.metadata.installer_key || "").trim();
  const hubToolSlug = hubLauncherToolSlug(hubRelease.metadata);
  if (!version || !hubToolSlug || !isHubLauncherArtifactKey(installerKey, version, `ManoLauncher-Setup-${version}.exe`, hubToolSlug)) {
    return json({ error: "launcher installer not found" }, 404);
  }
  const credentials = hubRelease.credentials;
  const headUrl = await presignR2Url(env, "HEAD", installerKey, 60, {
    canonicalHeaders: `host:${r2Host(env)}\n`,
    signedHeaders: "host",
    ...credentials,
  });
  const exists = await fetch(headUrl, { method: "HEAD" });
  if (!exists.ok) return json({ error: "launcher installer not found" }, exists.status === 404 ? 404 : 503);
  return new Response(null, {
    status: 302,
    headers: {
      Location: await presignGet(env, installerKey, credentials),
      "Cache-Control": "no-store",
    },
  });
}

function hubR2Credentials(env) {
  const bucketName = String(env.HUB_R2_BUCKET_NAME || "").trim();
  const accessKeyId = String(env.HUB_R2_ACCESS_KEY_ID || "").trim();
  const secretAccessKey = String(env.HUB_R2_SECRET_ACCESS_KEY || "").trim();
  if (!bucketName || !accessKeyId || !secretAccessKey) return null;
  return { bucketName, accessKeyId, secretAccessKey };
}

async function readHubLauncherMetadata(env, key) {
  const credentials = hubR2Credentials(env);
  if (!credentials) return null;
  const response = await fetch(await presignGet(env, key, credentials));
  if (response.status === 404) return null;
  if (!response.ok) throw new Error("Hub launcher metadata could not be read");
  const metadata = await response.json();
  if (!metadata || typeof metadata !== "object")
    throw new Error("Hub launcher metadata is invalid");
  return { metadata, credentials };
}

const HUB_LAUNCHER_TOOL_SLUGS = new Set(["mano-launcher", "gamelauncher"]);

function hubLauncherToolSlug(metadata) {
  const slug = String(metadata.tool_slug || "mano-launcher").trim();
  return HUB_LAUNCHER_TOOL_SLUGS.has(slug) ? slug : "";
}

function isHubLauncherArtifactKey(key, version, filename, toolSlug) {
  const parts = String(key || "").split("/");
  return (
    HUB_LAUNCHER_TOOL_SLUGS.has(toolSlug) &&
    parts.length === 5 &&
    parts[0] === "artifacts" &&
    parts[1] === toolSlug &&
    parts[2] === version &&
    /^[0-9a-f-]{36}$/.test(parts[3]) &&
    parts[4] === filename
  );
}

async function launcherHistory(request, env) {
  const url = new URL(request.url);
  const channel = normalizeChannel(url.searchParams.get("channel"), "live");
  const projectId = url.searchParams.get("project_id") || env.LAUNCHER_PROJECT_ID || "";
  const bundleId = url.searchParams.get("bundle_id") || env.LAUNCHER_BUNDLE_ID || "";
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  let query = "";
  let params = [];

  if (projectId) {
    query = "SELECT * FROM builds WHERE project_id = ? AND channel = ? ORDER BY created_at DESC LIMIT ?";
    params = [projectId, channel, limit];
  } else if (bundleId) {
    query = "SELECT builds.* FROM builds JOIN projects ON projects.id = builds.project_id WHERE projects.bundle_id = ? AND builds.channel = ? ORDER BY builds.created_at DESC LIMIT ?";
    params = [bundleId, channel, limit];
  } else {
    query = "SELECT * FROM builds WHERE channel = ? ORDER BY created_at DESC LIMIT ?";
    params = [channel, limit];
  }

  const { results } = await env.DB.prepare(query).bind(...params).all();
  const releases = await Promise.all((results || []).map(async row => {
    const build = await rowToBuild(env, row, url.origin);
    const { full, patches } = launcherArtifacts(build?.manifest?.files || [], build.version);
    const mandatoryTag = String(build.tag || "").toLowerCase();
    return {
      build_id: build.id,
      project_id: build.project_id,
      version: build.version,
      created_at: build.created_at,
      is_mandatory: mandatoryTag.includes("force") || mandatoryTag.includes("mandatory"),
      notes: build.changelog || "No release notes.",
      full_url: full?.download_url || full?.storage_url || "",
      full_hash: full?.hash || "",
      full_size: Number(full?.size || 0),
      patches,
    };
  }));

  return json({ channel, releases });
}

function launcherArtifacts(files, latestVersion) {
  const list = Array.isArray(files) ? files : [];
  const fullCandidates = list.filter(file => isLauncherFullArtifact(file.path));
  const full = fullCandidates.find(file => isTrustedIntegrity(file)) || fullCandidates[0] || list[0] || null;
  const patches = list
    .filter(file => isPatchArtifact(file.path))
    .map(file => {
      const parsed = parsePatchVersions(file.path, latestVersion);
      if (!parsed) return null;
      if (!isTrustedIntegrity(file)) return null;
      return {
        from_version: parsed.from_version,
        to_version: parsed.to_version,
        patch_url: file.download_url || file.storage_url || "",
        hash: file.hash || "",
        size: Number(file.size || 0),
      };
    })
    .filter(Boolean);
  return { full, patches };
}

function isLauncherFullArtifact(path) {
  const text = String(path || "").toLowerCase();
  const fullExt = /\.(exe|msi|zip|dmg|pkg|appimage)$/;
  return fullExt.test(text) && (text.includes("full") || text.includes("setup") || text.includes("installer") || !text.includes("patch"));
}

function isPatchArtifact(path) {
  const text = String(path || "").toLowerCase();
  return text.includes("patch") || /\.patch(\.|$)/.test(text) || /\.delta(\.|$)/.test(text);
}

function parsePatchVersions(path, latestVersion) {
  const text = String(path || "").toLowerCase();
  const explicit = text.match(/(?:from[-_v]*)?(\d+\.\d+\.\d+)[-_.]*(?:to|->)[-_v]*(\d+\.\d+\.\d+)/i);
  if (explicit) return { from_version: explicit[1], to_version: explicit[2] };
  const single = text.match(/patch[-_v]*(\d+\.\d+\.\d+)/i);
  if (single) return { from_version: single[1], to_version: latestVersion };
  return null;
}

function isTrustedIntegrity(file) {
  const hash = String(file?.hash || "").trim();
  return hash.length >= 32;
}

function compareVersions(left, right) {
  const a = String(left || "").split(".").map(part => Number.parseInt(part, 10) || 0);
  const b = String(right || "").split(".").map(part => Number.parseInt(part, 10) || 0);
  const limit = Math.max(a.length, b.length);
  for (let index = 0; index < limit; index += 1) {
    const diff = (a[index] || 0) - (b[index] || 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  return 0;
}

async function downloadArtifact(request, env, user, key, signatureValid, ctx) {
  if (!key.startsWith("builds/")) return json({ error: "invalid object path" }, 400);
  const url = new URL(request.url);
  const signed = signatureValid ?? await validArtifactSignature(env, key, url.searchParams);
  if (!user && !signed) return json({ error: "unauthorized" }, 401);

  const startedAt = Date.now();
  let range = null;
  let object;
  const rangeHeader = request.method === "GET" ? request.headers.get("Range") : null;
  if (request.method === "HEAD" || rangeHeader) {
    object = await env.BUILDS_BUCKET.head(key);
    if (!object) return json({ error: "artifact not found" }, 404);
    if (rangeHeader && artifactIfRangeMatches(request.headers.get("If-Range"), object)) {
      range = artifactByteRange(rangeHeader, object.size);
      if (range === false) {
        return new Response(null, { status: 416, headers: {
          "Content-Range": `bytes */${object.size}`,
          "Accept-Ranges": "bytes",
          "Cache-Control": "private, no-store",
        } });
      }
    }
  }
  if (request.method !== "HEAD") {
    const metadata = object;
    object = await env.BUILDS_BUCKET.get(key, range ? {
      range,
      // Pin the range to the version inspected by head(). If the object changes,
      // send the complete new version, never bytes from two different versions.
      onlyIf: { etagMatches: metadata.etag },
    } : undefined);
    if (object && !object.body) {
      range = null;
      object = await env.BUILDS_BUCKET.get(key);
    }
  }
  if (!object) return json({ error: "artifact not found" }, 404);

  const r2DurationMs = Date.now() - startedAt;
  const length = range ? range.length : object.size;
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Last-Modified", object.uploaded.toUTCString());
  headers.set("Accept-Ranges", "bytes");
  headers.set("Content-Length", String(length));
  headers.set("Cache-Control", "private, max-age=300, no-transform");
  headers.set("Server-Timing", `r2;dur=${r2DurationMs}`);
  // A diagnostic fallback for runtimes which remove Content-Length on HEAD.
  headers.set("X-Artifact-Size", String(object.size));
  if (range) headers.set("Content-Range", `bytes ${range.offset}-${range.offset + range.length - 1}/${object.size}`);
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/octet-stream");
  const status = range ? 206 : 200;
  console.log(JSON.stringify({ event: "artifact_download", key, method: request.method,
    status, bytes: length, offset: range?.offset ?? 0, r2DurationMs,
    colo: request.cf?.colo ?? null, ray: request.headers.get("cf-ray"), auth: signed ? "signature" : "session" }));
  if (request.method === "HEAD") return new Response(null, { headers });

  let body = object.body;
  if (ctx && typeof FixedLengthStream !== "undefined") {
    // Workers ignores a manually set Content-Length for ordinary streams.
    // FixedLengthStream preserves streaming/backpressure and enforces byte count.
    const stream = new FixedLengthStream(length);
    ctx.waitUntil(body.pipeTo(stream.writable).catch(() => {
      console.warn(JSON.stringify({ event: "artifact_stream_interrupted", key, bytes: length }));
    }));
    body = stream.readable;
  }
  return new Response(body, { status, headers, encodeBody: "manual" });
}

function artifactIfRangeMatches(value, object) {
  if (!value) return true;
  // R2 supplies a strong ETag. Weak tags and dates are ignored conservatively:
  // an upload timestamp alone cannot prove no second write occurred that second.
  return value === object.httpEtag && !value.startsWith("W/");
}

function artifactByteRange(value, size) {
  // Ignore malformed/multiple ranges, returning 200 as HTTP permits. Support
  // closed, open-ended and suffix ranges without allocating the complete file.
  const match = /^bytes=(\d*)-(\d*)$/i.exec(value.trim());
  if (!match || (!match[1] && !match[2])) return null;
  const first = match[1] ? Number(match[1]) : null;
  const last = match[2] ? Number(match[2]) : null;
  if ((first !== null && !Number.isSafeInteger(first)) || (last !== null && !Number.isSafeInteger(last))) return null;
  if (!size || (first !== null && first >= size) || (first === null && last === 0)) return false;
  if (first !== null && last !== null && last < first) return null;
  const offset = first ?? Math.max(0, size - last);
  const end = first === null || last === null ? size - 1 : Math.min(last, size - 1);
  return { offset, length: end - offset + 1 };
}

async function validArtifactSignature(env, key, params) {
  const expires = Number(params.get("expires") || 0);
  const signature = params.get("signature") || "";
  if (!Number.isSafeInteger(expires) || expires < Math.floor(Date.now() / 1000)
      || !/^[a-f0-9]{64}$/.test(signature) || !env.R2_SECRET_ACCESS_KEY) return false;
  const signingKey = await crypto.subtle.importKey("raw", encoder.encode(env.R2_SECRET_ACCESS_KEY),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return crypto.subtle.verify("HMAC", signingKey, hexToBytes(signature), encoder.encode(`${key}.${expires}`));
}

async function nextVersion(env, projectId, icon) {
  // A single atomic write allocates the number, including simultaneous upload starts.
  const counter = await env.DB.prepare(
    "INSERT INTO project_build_counters (project_id, last_number) VALUES (?, 1) ON CONFLICT(project_id) DO UPDATE SET last_number = last_number + 1 RETURNING last_number"
  ).bind(projectId).first();
  return `${String(icon || "GM").trim()}-Build-${counter.last_number}`;
}



async function rowToBuild(env, row, baseUrl = "") {
  if (!row) return null;
  const channel = normalizeChannel(row.channel);
  const manifest = row.manifest_json ? await manifestWithDownloadUrls(env, JSON.parse(row.manifest_json), baseUrl) : null;
  const files = Array.isArray(manifest?.files) ? manifest.files : [];
  const primaryFile = files[0] || {};
  const downloadUrl = primaryFile.download_url || primaryFile.storage_url || "";
  return {
    ...row,
    build_id: row.id,
    channel,
    date: row.created_at || "",
    uploaded_at: row.uploaded_at || row.created_at || "",
    size: Number(row.total_size || manifest?.total_size || 0),
    download_url: downloadUrl,
    known_issues: parseMetadataList(row.known_issues),
    focus_areas: parseMetadataList(row.focus_areas),
    test_instructions: row.test_instructions || "",
    save_path_hint: row.save_path_hint || "",
    config_path_hint: row.config_path_hint || "",
    commit_sha: row.commit_sha || "",
    uploaded_by: row.uploaded_by || "",
    manifest_id: row.manifest_id || "",
    checksum: row.checksum || row.manifest_id || "",
    branch: row.branch || "",
    build_source: row.build_source || "",
    manifest,
  };
}

function projectToPayload(project) {
  if (!project) return null;
  return {
    ...project,
    banner_title: project.banner_title || project.name || "",
    banner_subtitle: project.banner_subtitle || project.description || "",
    description: project.description || "",
    cover_url: project.cover_url || "",
    known_issues: parseMetadataList(project.known_issues),
    focus_areas: parseMetadataList(project.focus_areas),
    test_instructions: project.test_instructions || "",
    maintenance_notice: project.maintenance_notice || "",
    save_path_hint: project.save_path_hint || "",
    config_path_hint: project.config_path_hint || "",
    recommended_profile: project.recommended_profile || "",
  };
}

function projectMetadataFromForm(form, existing = {}) {
  return {
    banner_title: formValueOrExisting(form, existing, "banner_title"),
    banner_subtitle: formValueOrExisting(form, existing, "banner_subtitle"),
    description: formValueOrExisting(form, existing, "description"),
    cover_url: formValueOrExisting(form, existing, "cover_url"),
    known_issues: formValueOrExisting(form, existing, "known_issues"),
    test_instructions: formValueOrExisting(form, existing, "test_instructions"),
    focus_areas: formValueOrExisting(form, existing, "focus_areas"),
    maintenance_notice: formValueOrExisting(form, existing, "maintenance_notice"),
    save_path_hint: formValueOrExisting(form, existing, "save_path_hint"),
    config_path_hint: formValueOrExisting(form, existing, "config_path_hint"),
    recommended_profile: formValueOrExisting(form, existing, "recommended_profile"),
  };
}

function formValueOrExisting(form, existing, key) {
  return form.has(key) ? field(form, key) : existing?.[key] || "";
}

function stringField(source, key) {
  return String(source?.[key] || "").trim();
}

function metadataText(source, key) {
  const value = source?.[key];
  return Array.isArray(value) ? JSON.stringify(value) : String(value || "").trim();
}

function parseMetadataList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(item => String(item).trim()).filter(Boolean);
  const text = String(value).trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed.map(item => String(item).trim()).filter(Boolean);
  } catch {
  }
  return text.split(/\r?\n/).map(item => item.replace(/^[-*]\s*/, "").trim()).filter(Boolean);
}

function normalizeChannel(value, fallback = "dev") {
  const channel = String(value || fallback).trim().toLowerCase();
  return CHANNELS.includes(channel) ? channel : fallback;
}

function roleRank(role) {
  return {
    viewer: 0,
    QA: 1,
    dev: 2,
    admin: 3,
  }[role] ?? -1;
}

function canAccessProject(user, project) {
  if (!project) return false;
  if (user?.auth_type === "project-token") return user.project_id === project.id;
  const requiredRole = project.role || "viewer";
  const effectiveRole = user?.role || "viewer";
  return roleRank(effectiveRole) >= roleRank(requiredRole);
}

function visibleChannelsForRole(role) {
  if (role === "admin" || role === "dev") return ["dev", "qa", "live", "deprecated"];
  if (role === "QA") return ["qa", "live", "deprecated"];
  return ["live"];
}

function runtimeEnvironmentsForRole(role) {
  return role === "viewer" || !role ? ["production"] : ["dev", "staging", "production"];
}

function canAssign(user, channel) {
  if (user?.auth_type === "project-token") return user.allowed_channels.includes(channel);
  const role = typeof user === "string" ? user : user?.role;
  if (role === "admin") return true;
  if (role === "dev") return channel === "dev" || channel === "qa";
  if (role === "QA") return channel === "qa";
  return false;
}

async function presignPut(env, key, contentType) {
  return presignR2Url(env, "PUT", key, 1800, {
    canonicalHeaders: `content-type:${contentType}\nhost:${r2Host(env)}\n`,
    signedHeaders: "content-type;host",
  });
}

async function presignGet(env, key, credentials = {}) {
  return presignR2Url(env, "GET", key, 3600, {
    canonicalHeaders: `host:${r2Host(env)}\n`,
    signedHeaders: "host",
    ...credentials,
  });
}

async function presignR2Url(env, method, key, expires, options) {
  const host = r2Host(env);
  const bucketName = options.bucketName || env.R2_BUCKET_NAME;
  const accessKeyId = options.accessKeyId || env.R2_ACCESS_KEY_ID;
  const secretAccessKey = options.secretAccessKey || env.R2_SECRET_ACCESS_KEY;
  if (!bucketName || !accessKeyId || !secretAccessKey)
    throw new Error("R2 signing credentials are not configured");
  const path = r2Path(env, key, bucketName);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/auto/s3/aws4_request`;
  const credential = `${accessKeyId}/${credentialScope}`;
  const params = new URLSearchParams({
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": credential,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expires),
    "X-Amz-SignedHeaders": options.signedHeaders,
  });
  const canonicalQuery = [...params.entries()].map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).sort().join("&");
  const canonicalRequest = [method, path, canonicalQuery, options.canonicalHeaders, options.signedHeaders, "UNSIGNED-PAYLOAD"].join("\n");
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, credentialScope, await sha256Hex(canonicalRequest)].join("\n");
  const signingKey = await signatureKey(secretAccessKey, dateStamp, "auto", "s3");
  const signature = await hmacHex(signingKey, stringToSign);
  return `https://${host}${path}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

function r2Host(env) {
  return `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
}

function r2Path(env, key, bucketName = env.R2_BUCKET_NAME) {
  return `/${bucketName}/${encodeURIComponent(key).replaceAll("%2F", "/")}`;
}

async function manifestWithDownloadUrls(env, manifest, baseUrl = "") {
  const updated = { ...(manifest || {}) };
  updated.files = await Promise.all((updated.files || []).map(async file => {
    const entry = { ...file };
    const key = entry.storage_object || entry.object_path;
    if (key) {
      const downloadUrl = await objectDownloadUrl(env, key, baseUrl);
      entry.storage_object = key;
      entry.storage_url = downloadUrl;
      entry.download_url = downloadUrl;
    }
    return entry;
  }));
  return updated;
}

async function objectDownloadUrl(env, key, baseUrl = "") {
  const dashboardBase = (env.DASHBOARD_PUBLIC_URL || baseUrl || "").replace(/\/$/, "");
  if (dashboardBase) return `${dashboardBase}/api/artifacts/${encodeObjectPath(key)}?${await artifactSignatureParams(env, key)}`;

  const base = (env.R2_PUBLIC_URL || "").replace(/\/$/, "");
  return base ? `${base}/${key}` : presignGet(env, key);
}

function encodeObjectPath(key) {
  return String(key || "").split("/").map(part => encodeURIComponent(part)).join("/");
}

async function artifactSignatureParams(env, key) {
  const expires = Math.floor(Date.now() / 1000) + 3600;
  const signature = await hmacHex(encoder.encode(env.R2_SECRET_ACCESS_KEY), `${key}.${expires}`);
  return new URLSearchParams({ expires: String(expires), signature }).toString();
}

async function signatureKey(secret, dateStamp, region, service) {
  const kDate = await hmacBytes(encoder.encode(`AWS4${secret}`), dateStamp);
  const kRegion = await hmacBytes(kDate, region);
  const kService = await hmacBytes(kRegion, service);
  return hmacBytes(kService, "aws4_request");
}

function objectPathFor(projectId, buildId, filename, index) {
  const clean = (filename || `build-file-${index}`).replace(/[^\w.\-]+/g, "_") || `build-file-${index}`;
  return `builds/${projectId}/${buildId}/files/${String(index).padStart(3, "0")}-${clean}`;
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt);
  return `pbkdf2:${bytesToHex(salt)}:${bytesToHex(hash)}`;
}

async function verifyPassword(password, stored) {
  const [, saltHex, hashHex] = String(stored || "").split(":");
  if (!saltHex || !hashHex) return false;
  const hash = await pbkdf2(password, hexToBytes(saltHex));
  return bytesToHex(hash) === hashHex;
}

async function pbkdf2(password, salt) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PASSWORD_HASH_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return new Uint8Array(bits);
}

async function sha256Hex(value) {
  const data = typeof value === "string" ? encoder.encode(value) : value;
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}

async function hmacBytes(keyBytes, value) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

async function hmacHex(keyBytes, value) {
  return bytesToHex(await hmacBytes(keyBytes, value));
}

function bytesToHex(bytes) {
  return [...bytes].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function field(form, name) {
  return String(form.get(name) || "").trim();
}

async function createSession(request, env) {
  const payload = request.headers.get("content-type")?.includes("application/json")
    ? await request.json()
    : Object.fromEntries(await request.formData());
  const email = String(payload.email || "").trim().toLowerCase();
  const password = String(payload.password || "");
  const user = await env.DB.prepare("SELECT email, role, password_hash FROM users WHERE email = ?").bind(email).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return { ok: false, error: "Invalid email or password" };
  }
  const token = crypto.randomUUID() + crypto.randomUUID();
  const now = new Date();
  const expires = new Date(now.getTime() + 7 * 86400 * 1000);
  await env.DB.prepare("INSERT INTO sessions (token_hash, email, expires_at, created_at) VALUES (?, ?, ?, ?)")
    .bind(await sha256Hex(token), email, expires.toISOString(), now.toISOString())
    .run();
  return {
    ok: true,
    user: { email: user.email, role: user.role },
    cookie: `sid=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
  };
}

async function clearSession(request, env) {
  const token = cookie(request, "sid");
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Hex(token)).run();
  }
}

function expiredSessionCookie() {
  return "sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
}

function cookie(request, name) {
  return Object.fromEntries((request.headers.get("Cookie") || "").split(";").map(part => {
    const [key, ...value] = part.trim().split("=");
    return [key, value.join("=")];
  }))[name];
}

function nowIso() {
  return new Date().toISOString();
}

function redirect(location, headers = {}) {
  return new Response(null, { status: 302, headers: { Location: location, ...headers } });
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } });
}

function html(body, status = 200) {
  return new Response(decorateHtml(body), { status, headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function decorateHtml(body) {
  const isLogin = body.includes("<title>Login</title>");
  const isDashboard = body.includes("<title>Build Producer Dashboard</title>");
  if (!isLogin && !isDashboard) return body;

  let decorated = body
    .replace("</head>", `<style>${MODERN_THEME_STYLE}</style><style>${adminStyle}</style></head>`)
    .replace("<title>Login</title>", "<title>Login | Game Build Dashboard</title>")
    .replace("<title>Build Producer Dashboard</title>", "<title>Game Build Dashboard</title>")
    .replace("Dashboard API / R2 Storage / D1 Metadata / Role Auth", "Game build operations");

  if (isLogin) {
    decorated = decorated.replace(
      '<main class="login panel">',
      `<main class="login panel">${themeToggleMarkup()}`,
    );
  }
  if (isDashboard) return decorated.replace("</body>", () => `<script>${adminScript}</script></body>`);
  return `${decorated}${themeScript()}`;
}

function themeToggleMarkup() {
  return `<button class="icon-button theme-toggle" type="button" data-theme-toggle aria-label="Switch to light theme" title="Switch theme"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="3.5"></circle><path d="M12 2.5v2M12 19.5v2M4.1 4.1l1.4 1.4M18.5 18.5l1.4 1.4M2.5 12h2M19.5 12h2M4.1 19.9l1.4-1.4M18.5 5.5l1.4-1.4"></path></svg></button>`;
}

function themeScript() {
  return `<script>(function(){const key="game-build-dashboard-theme";function applyTheme(theme){document.documentElement.dataset.theme=theme;try{window.localStorage.setItem(key,theme)}catch{}document.querySelectorAll("[data-theme-toggle]").forEach(button=>{const next=theme==="dark"?"light":"dark";button.setAttribute("aria-label","Switch to "+next+" theme");button.setAttribute("title","Switch to "+next+" theme")})}let initial="dark";try{initial=window.localStorage.getItem(key)==="light"?"light":"dark"}catch{}applyTheme(initial);document.querySelectorAll("[data-theme-toggle]").forEach(button=>button.addEventListener("click",()=>applyTheme(document.documentElement.dataset.theme==="dark"?"light":"dark")))})();</script>`;
}

function notFound() {
  return html("<h1>Not Found</h1>", 404);
}

function legacyTooLargeResponse() {
  return json({ error: "Use /uploads/init direct-to-R2 upload flow for build files." }, 400);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
}

function loginPage(error = "") {
  return html(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>${style()}</head><body><main class="login panel"><div class="brand"><div class="mark">M</div><div><h1>Mano Dashboard</h1><p>Internal playtesting workspace</p></div></div>${error ? `<div class="alert">${escapeHtml(error)}</div>` : ""}<p>Use a Google account that an admin has added to Dashboard access.</p><a class="button" href="/api/auth/google/start">Continue with Google</a></main></body></html>`);
}

function renderDashboard({ user, projects, selected, builds, users }) {
  const latest = builds[0];
  return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Build Producer Dashboard</title>${style()}</head><body><div class="shell"><aside class="sidebar"><div class="brand"><div class="mark">BP</div><div><h1>Build Producer</h1><p>Cloudflare R2 + D1</p></div></div><div class="account"><strong>${escapeHtml(user.email)}</strong><span>role: ${escapeHtml(user.role)}</span><form method="post" action="/logout" data-loading-steps="Signing out|Clearing session"><button class="button secondary">Logout</button></form></div><div><div class="tiny">Projects</div><nav class="project-list">${projects.map(project => `<a class="project-link ${selected?.id === project.id ? "active" : ""}" href="/?project=${project.id}" data-loading-steps="Opening project|Loading builds"><div class="project-icon">${escapeHtml(project.icon.slice(0, 2).toUpperCase())}</div><div class="truncate"><strong>${escapeHtml(project.name)}</strong><span>${escapeHtml(project.bundle_id)}</span></div></a>`).join("")}</nav></div>${user.role === "admin" ? createProjectForm() : ""}</aside><main class="main">${selected ? projectView(user, selected, builds, latest, users) : emptyView()}</main></div>${softLoad()}${dashboardScript()}</body></html>`;
}

function createProjectForm() {
  return `<form class="form-grid" method="post" action="/projects" data-loading-steps="Creating project|Saving project data|Refreshing dashboard"><h3>Create Project</h3><label class="field"><span class="label">Project name</span><input name="name" required></label><label class="field"><span class="label">Icon</span><input name="icon" maxlength="4" placeholder="GM"></label><label class="field"><span class="label">Bundle ID</span><input name="bundle_id" required></label><label class="field"><span class="label">Role</span><select name="role">${["viewer", "QA", "dev", "admin"].map(role => `<option>${role}</option>`).join("")}</select></label><button class="button">+ Project</button></form>`;
}

function projectView(user, project, builds, latest, users) {
  return `<section class="topbar"><div><div class="label">Dashboard API / R2 Storage / D1 Metadata / Role Auth</div><h2>${escapeHtml(project.name)}</h2><p>${escapeHtml(project.bundle_id)}</p></div><div class="actions">${latest ? `<a class="button secondary" href="/builds/${latest.id}/manifest" data-loading-steps="Opening manifest|Loading build metadata">Manifest</a>` : ""}<a class="button secondary" href="/api/projects/${project.id}/builds" data-loading-steps="Opening API response|Loading project builds">API</a></div></section><section class="grid"><div class="panel">${projectManagement(user, project, builds, latest)}</div>${["admin", "dev"].includes(user.role) ? uploadPanel(user, project) : ""}</section>${user.role === "admin" ? userAccess(users, user) : ""}${buildHistory(user, project, builds)}`;
}

function discordWebhookPanel(project, state = null) {
  const settings = state || { configured: false, enabled: false, channels: [...CHANNELS] };
  const status = settings.last_error ? `Last delivery failed: ${settings.last_error}` : settings.last_sent_at ? `Last message sent (UTC): ${settings.last_sent_at.replace("T", " ").slice(0, 19)}` : "No messages sent yet.";
  return `<section class="surface" id="project-discord-webhook" data-discord-panel data-discord-endpoint="/api/projects/${encodeURIComponent(project.id)}/discord-webhook"><div class="surface-header"><div><h2>Discord notifications</h2><p>Notify your Discord channel when a build upload completes.</p></div><span class="channel-tag" data-discord-configured>${settings.configured ? "Webhook saved" : "Not configured"}</span></div><div class="surface-body"><form class="form-grid" data-discord-settings><label class="discord-enabled"><input type="checkbox" name="enabled" ${settings.enabled ? "checked" : ""}>Enable build upload notifications</label><label>Discord webhook URL<input type="password" name="webhook_url" autocomplete="off" spellcheck="false" maxlength="512" placeholder="${settings.configured ? "Leave blank to keep the saved webhook" : "https://discord.com/api/webhooks/…"}"><small>Create an incoming webhook in the destination Discord channel, then paste its URL here. The saved URL is never shown again.</small></label><fieldset class="token-channels"><legend>Notify for upload channels</legend>${CHANNELS.map(channel => `<label><input type="checkbox" name="channels" value="${channel}" ${settings.channels.includes(channel) ? "checked" : ""}>${({ dev: "Development", qa: "QA", live: "Live", deprecated: "Deprecated" })[channel]}</label>`).join("")}</fieldset><div class="actions discord-actions"><button class="btn" type="submit">Save notifications</button><button class="btn secondary" type="button" data-discord-test ${settings.configured ? "" : "disabled"}>Send test message</button><button class="btn secondary danger-text" type="button" data-discord-remove ${settings.configured ? "" : "disabled"}>Remove webhook</button></div></form><p class="muted section-gap">Messages include the project, build version, upload channel, package size, and a link to the build. Failed notifications do not interrupt uploads.</p><p role="status" class="muted section-gap" data-discord-status>${escapeHtml(status)}</p></div></section>`;
}

function apiTokenPanel(project, tokens = []) {
  const endpoint = `/api/projects/${encodeURIComponent(project.id)}/tokens`;
  const now = nowIso();
  const status = token => token.revoked_at ? "Revoked" : token.expires_at && token.expires_at <= now ? "Expired" : "Active";
  const tokenRows = tokens.map(token => `<tr><td><strong>${escapeHtml(token.name)}</strong><div class="cell-secondary mono">${escapeHtml(token.token_prefix)}…</div></td><td>${escapeHtml(token.channels.join(", "))}</td><td>${status(token)}</td><td>${escapeHtml(token.expires_at?.slice(0, 10) || "Never")}</td><td>${escapeHtml(token.last_used_at?.replace("T", " ").slice(0, 19) || "Not used")}</td><td>${token.revoked_at ? "—" : `<button type="button" class="btn secondary small danger-text" data-token-revoke="${escapeHtml(token.id)}">Revoke</button>`}</td></tr>`).join("");
  return `<section class="surface" id="project-api-tokens" data-token-panel data-token-endpoint="${escapeHtml(endpoint)}"><div class="surface-header"><div><h2>API tokens</h2><p>Create separate credentials for this project's build workflows.</p></div></div><div class="surface-body"><div class="api-token-context"><label>Project ID<input value="${escapeHtml(project.id)}" readonly></label><button type="button" class="btn secondary small" data-copy="${escapeHtml(project.id)}">Copy project ID</button></div><form class="form-grid section-gap" data-token-create><label>Token name<input name="name" maxlength="100" placeholder="e.g. GitHub Windows build" required></label><fieldset class="token-channels"><legend>Allowed upload channels</legend>${["dev", "qa", "live"].map(channel => `<label><input type="checkbox" name="channels" value="${channel}" ${channel === "dev" ? "checked" : ""}>${({ dev: "Development", qa: "QA", live: "Live" })[channel]}</label>`).join("")}</fieldset><label>Expires after<select name="expires_in_days"><option value="30">30 days</option><option value="90" selected>90 days</option><option value="365">365 days</option><option value="0">Never</option></select></label><div><button class="btn" type="submit">Create token</button></div></form><p class="muted section-gap">Tokens can upload only to this project and the selected channels. Save the generated value as the DASHBOARD_API_TOKEN secret in the game's GitHub repository.</p><div class="api-token-result section-gap" data-token-result hidden><strong>Copy this token now</strong><p>The full value is shown only once. Keep this page open until you have saved it.</p><label>API token<input data-token-value readonly autocomplete="off" spellcheck="false"></label><div class="actions section-gap"><button type="button" class="btn secondary small" data-token-copy>Copy token</button><button type="button" class="btn secondary small" data-token-done>I have saved it</button></div></div><p role="status" class="muted section-gap" data-token-status></p></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Channels</th><th>Status</th><th>Expires (UTC)</th><th>Last used (UTC)</th><th>Action</th></tr></thead><tbody data-token-list>${tokenRows || '<tr><td colspan="6">No API tokens for this project yet.</td></tr>'}</tbody></table></div></section>`;
}

function projectManagement(user, project, builds, latest) {
  const id = encodeURIComponent(project.id);
  return `<section class="surface settings-project" id="project-general"><div class="surface-header"><div><h2>General</h2><p>Project identity and the minimum role needed for access.</p></div><span class="channel-tag">${escapeHtml(project.role || 'viewer')} access</span></div><div class="surface-body">${user.role === "admin" ? `<form class="form-grid" method="post" action="/projects/${id}" data-loading-steps="Saving project|Updating project|Refreshing dashboard"><div class="grid-2"><label>Project name<input name="name" value="${escapeHtml(project.name)}" required></label><label>Project icon<input name="icon" value="${escapeHtml(project.icon)}" maxlength="4"><small>Up to four characters.</small></label></div><label>Bundle ID<input name="bundle_id" value="${escapeHtml(project.bundle_id)}" required><small>The application identifier used by your project.</small></label><label>Minimum access role<select name="role">${["viewer", "QA", "dev", "admin"].map(role => `<option ${project.role === role ? "selected" : ""}>${role}</option>`).join("")}</select></label><div class="form-footer"><button class="button" type="submit">Save changes</button></div></form>` : `<dl class="metadata-list">${[['Name', project.name], ['Bundle ID', project.bundle_id], ['Minimum role', project.role]].map(([label,value])=>`<div><dt>${label}</dt><dd>${escapeHtml(value || 'Not provided')}</dd></div>`).join('')}</dl><p class="muted section-gap">An admin can change project settings.</p>`}</div></section>${user.role === 'admin' ? `<section class="surface danger-zone" id="danger-zone"><div class="surface-header"><div><h2>Danger zone</h2><p>Permanent actions affecting this project and its files.</p></div></div><div class="surface-body danger-row"><div><strong>Delete project</strong><p>Remove this project and every build package it contains.</p></div><form method="post" action="/projects/${id}/delete" data-confirm="Delete this project and all builds? This cannot be undone."><button class="button danger" type="submit">Delete project</button></form></div></section>` : ''}`;
}

function uploadPanel(user, project) {
  const id = encodeURIComponent(project.id);
  return `<div class="upload-layout"><form id="build-upload" class="release-upload" data-direct-upload="true" data-init-url="/api/projects/${id}/uploads/init" data-complete-base="/api/projects/${id}/uploads" data-return-url="/?view=builds&project=${id}"><section class="surface upload-section" id="upload-package"><div class="surface-header"><div class="numbered-heading"><span>01</span><div><h2>Build package</h2><p>Select the artifact you want to distribute.</p></div></div></div><div class="surface-body"><label class="dropzone"><input type="file" name="build" multiple required aria-label="Build package"><span><span class="upload-glyph" aria-hidden="true">↑</span><strong>Drop your build files here</strong><span>or click to browse · ZIP packages or standalone files</span></span></label></div></section><section class="surface upload-section" id="upload-release"><div class="surface-header"><div class="numbered-heading"><span>02</span><div><h2>Release settings</h2><p>Choose who can access this build.</p></div></div></div><div class="surface-body form-grid"><div class="grid-2"><label>Version<input value="${escapeHtml(project.icon)}-Build-(auto)" readonly aria-label="Automatically generated version"><small>A unique version is generated for each upload.</small></label><label>Release channel<select name="channel">${CHANNELS.filter(c => user.role === "admin" || c !== "live").map(c => `<option value="${c}">${({dev:'Development',qa:'QA',live:'Live',deprecated:'Deprecated'})[c]}</option>`).join("")}</select><small data-channel-hint>Development builds are available to developers and admins.</small></label></div><label>Release tag <span class="optional-label">Optional</span><input name="tag" placeholder="e.g. hotfix, playtest-04"></label></div></section><section class="surface upload-section" id="upload-notes"><div class="surface-header"><div class="numbered-heading"><span>03</span><div><h2>Release notes</h2><p>Tell your team what changed and what to test.</p></div></div></div><div class="surface-body"><label>Changelog<textarea name="changelog" placeholder="Summarize changes, fixes, and test focus…"></textarea></label></div></section><div class="upload-footer"><p>Files are hashed and registered in an artifact manifest.</p><button class="button" type="submit">↑ Upload build</button></div></form><aside class="upload-aside"><section class="surface release-summary"><div class="surface-header"><h2>Release summary</h2><span class="draft-label">Draft</span></div><div class="surface-body"><div class="summary-project"><div class="project-icon">${escapeHtml((project.icon || project.name).slice(0,2).toUpperCase())}</div><div><strong>${escapeHtml(project.name)}</strong><span>${escapeHtml(project.bundle_id)}</span></div></div><dl class="metadata-list"><div><dt>Package</dt><dd data-summary-package>No files selected</dd></div><div><dt>Total size</dt><dd data-summary-size>—</dd></div><div><dt>Channel</dt><dd data-summary-channel>Development</dd></div><div><dt>Version</dt><dd>Generated on upload</dd></div><div><dt>Tag</dt><dd data-summary-tag>None</dd></div></dl><div class="release-destination"><span class="status-dot"></span><p>Available in Mano Launcher after upload completes.</p></div></div></section><div class="upload-guidance"><h3>Before you publish</h3><ul><li>Include the complete runnable build.</li><li>Choose the intended release channel.</li><li>Add test focus and known issues to your notes.</li></ul></div></aside></div>`;
}

function userAccess(users, currentUser) {
  return `<section class="surface access-control" id="workspace-access"><div class="surface-header"><div><h2>Team access</h2><p>Workspace-wide Google accounts and Dashboard roles.</p></div><span class="count-badge">${users.length} accounts</span></div><div class="surface-body"><form class="invite-form" method="post" action="/users"><label>Google account<input name="email" type="email" placeholder="name@yourstudio.com" required></label><label>Role<select name="role">${USER_ROLES.map(role => `<option>${role}</option>`).join("")}</select></label><button class="button" type="submit">Add account</button></form><div class="user-table">${users.map(u => userRow(u, currentUser)).join("")}</div><details class="role-reference"><summary>View role permissions</summary>${permissionMatrix()}</details></div></section>`;
}

function permissionMatrix() {
  const rows = [
    ["admin", "All dev tools plus users, project access, rollback, delete"],
    ["dev", "Upload builds, view dev/qa/live, play every environment"],
    ["QA", "View qa/live, play every environment, open and upload logs"],
    ["viewer", "Live builds only, production runtime only"],
  ];
  return `<div class="permission-grid">${rows.map(([role, text]) => `<div class="stat"><strong>${role}</strong><span>${text}</span></div>`).join("")}</div>`;
}

function userRow(accessUser, currentUser) {
  const email = escapeHtml(accessUser.email);
  const encodedEmail = encodeURIComponent(accessUser.email);
  const isSelf = accessUser.email === currentUser.email;
  return `<article class="access-row"><div><strong>${email}</strong><span>role: ${escapeHtml(accessUser.role)}${isSelf ? " / current user" : ""}</span></div><form class="inline-form" method="post" action="/users/${encodedEmail}/role" data-loading-steps="Updating role|Refreshing access list"><select name="role" aria-label="Role for ${email}">${USER_ROLES.map(role => `<option ${accessUser.role === role ? "selected" : ""} ${isSelf && role !== "admin" ? "disabled" : ""}>${role}</option>`).join("")}</select><button class="button secondary" type="submit">Save</button></form>${isSelf ? `<button class="button secondary" disabled>Protected</button>` : `<form method="post" action="/users/${encodedEmail}/delete" data-confirm="Delete ${email}?" data-loading-steps="Deleting user|Clearing sessions|Refreshing access list"><button class="button danger">Delete</button></form>`}</article>`;
}

function buildHistory(user, project, builds) {
  return `<section class="panel"><div class="build-head"><div><h3>Build History</h3><p>Rollback promotes a selected build back to live.</p></div><div class="code">POST /api/projects/${project.id}/uploads/init</div></div>${builds.length ? `<div class="build-list">${builds.map(build => buildCard(user, build)).join("")}</div>` : `<div class="empty">No builds yet.</div>`}</section>`;
}

function buildDetailsEditor(user, build) {
  if (!["admin", "dev"].includes(user.role)) return "";
  const listText = (key, title) => {
    const items = parseMetadataList(build[key]);
    return (items.length ? items : parseMetadataList(releaseSectionText(build.changelog, title))).join("\n");
  };
  return `<details class="build-details-editor" id="edit-build-details"><summary>Edit build details</summary><form class="form-grid section-gap" data-build-details data-details-url="/api/builds/${encodeURIComponent(build.id)}/details"><label>Release tag<input name="tag" maxlength="200" value="${escapeHtml(build.tag || "")}" placeholder="e.g. playtest, hotfix"></label><label>Test Focus<textarea name="focus_areas" maxlength="16000" placeholder="What should the team test? One item per line.">${escapeHtml(listText("focus_areas", "Test Focus"))}</textarea></label><label>Test instructions<textarea name="test_instructions" maxlength="16000" placeholder="Steps, expected results, and test setup…">${escapeHtml(build.test_instructions || "")}</textarea></label><label>Known Issues<textarea name="known_issues" maxlength="16000" placeholder="One issue per line.">${escapeHtml(listText("known_issues", "Known Issues"))}</textarea></label><label>Release notes<textarea name="changelog" data-plain-notes maxlength="64000" rows="8">${escapeHtml(build.changelog || "")}</textarea><small>Test Focus and Known Issues above update their sections in these notes when you save.</small></label><div class="grid-2"><label>Save path hint<input name="save_path_hint" maxlength="1024" value="${escapeHtml(build.save_path_hint || "")}"></label><label>Config path hint<input name="config_path_hint" maxlength="1024" value="${escapeHtml(build.config_path_hint || "")}"></label></div><p class="muted">You can update these details at any time, including after a playtest starts.</p><p role="status" data-details-status></p><div><button class="btn" type="submit">Save details</button></div></form></details>`;
}

function buildTestingNotes(build) {
  let content = "";
  for (const [key, title] of [["focus_areas", "Test Focus"], ["known_issues", "Known Issues"]]) {
    const items = parseMetadataList(build[key]);
    if (items.length && !releaseSectionRanges(build.changelog, title).length) content += `<h3>${title}</h3><ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
  }
  if (build.test_instructions) content += `<h3>Test instructions</h3><p class="testing-instructions">${escapeHtml(build.test_instructions)}</p>`;
  for (const [key, title] of [["save_path_hint", "Save path"], ["config_path_hint", "Config path"]]) {
    if (build[key]) content += `<h3>${title}</h3><p class="mono">${escapeHtml(build[key])}</p>`;
  }
  return content ? `<div class="release-notes section-gap">${content}</div>` : "";
}

function buildCard(user, build) {
  const channels = CHANNELS.filter(channel => canAssign(user.role, channel));
  const id = encodeURIComponent(build.id);
  return `<article class="build-release">${releaseNotesMarkup(build.changelog)}${buildTestingNotes(build)}${buildDetailsEditor(user, build)}<section class="release-controls" id="release-actions"><div><h3>Release actions</h3><p class="muted">Assign this artifact to a channel or promote it to live.</p></div>${channels.length ? `<form class="channel-assignment" method="post" action="/builds/${id}/channel"><label>Release channel<select name="channel">${channels.map(c => `<option value="${c}" ${build.channel === c ? "selected" : ""}>${({dev:'Development',qa:'QA',live:'Live',deprecated:'Deprecated'})[c]}</option>`).join("")}</select></label><button class="button secondary" type="submit">Assign channel</button></form>` : '<p class="muted">Your role can inspect this artifact. A developer or admin can manage its channel.</p>'}<div class="release-secondary-actions"><a class="button secondary" href="/builds/${id}/manifest" target="_blank" rel="noopener">Open manifest ↗</a>${user.role === "admin" ? `<form method="post" action="/builds/${id}/rollback"><button class="button secondary" type="submit">Promote to live</button></form>` : ''}</div>${["admin", "dev"].includes(user.role) ? `<details class="build-danger"><summary>Delete this build</summary><p class="muted">Permanently remove this version and its stored files.</p><form method="post" action="/builds/${id}/delete" data-confirm="Delete build version ${escapeHtml(build.version)}? This cannot be undone."><button class="button danger" type="submit">Delete build</button></form></details>` : ''}</section></article>`;
}

function releaseNotesMarkup(value) {
  if (!String(value || '').trim()) return '<p class="muted">No release notes provided for this build.</p>';
  const sections = [];
  let bullets = [];
  let code = null;
  const flush = () => { if (bullets.length) { sections.push('<ul>' + bullets.join('') + '</ul>'); bullets = []; } };
  for (const line of String(value).split(/\r?\n/)) {
    if (line.trim().startsWith('```')) {
      flush();
      if (code) { sections.push('<pre class="code-block">' + escapeHtml(code.join('\n')) + '</pre>'); code = null; }
      else code = [];
      continue;
    }
    if (code) { code.push(line); continue; }
    const heading = line.match(/^#{1,6}\s+(.+)$/);
    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    if (bullet) { bullets.push('<li>' + escapeHtml(bullet[1]) + '</li>'); continue; }
    flush();
    if (heading) sections.push('<h3>' + escapeHtml(heading[1]) + '</h3>');
    else if (line.trim()) sections.push('<p>' + escapeHtml(line) + '</p>');
  }
  flush();
  if (code) sections.push('<pre class="code-block">' + escapeHtml(code.join('\n')) + '</pre>');
  return '<div class="release-notes">' + sections.join('') + '</div>';
}

function emptyView() {
  return `<section class="panel empty"><div><h2>Create your first project</h2><p>Add a project to start uploading builds and generating manifests.</p></div></section>`;
}

function style() {
  return `<style>:root{--ink:#16211f;--muted:#5d6d66;--line:#dce5df;--panel:#fff;--page:#f4f7f2;--lime:#b7ff5a;--green:#188a55;--cyan:#1aa6b7;--rose:#ca3f64;--amber:#af7c18;--charcoal:#1f2a27;--shadow:0 16px 40px rgba(31,42,39,.08)}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--page);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input,select,textarea{font:inherit}button{border:0;cursor:pointer}button[disabled],select:disabled{cursor:not-allowed;opacity:.62}.shell{display:grid;grid-template-columns:280px minmax(0,1fr);min-height:100vh}.sidebar{background:var(--charcoal);color:#f8fff9;padding:24px;display:flex;flex-direction:column;gap:24px}.brand{display:flex;align-items:center;gap:12px}.mark,.project-icon{width:44px;height:44px;border-radius:8px;display:grid;place-items:center;background:var(--lime);color:var(--charcoal);font-weight:800}.brand h1{margin:0;font-size:19px;line-height:1.1}.brand p,.tiny,.sidebar span{color:#a9bab2;margin:0}.account{display:grid;gap:10px;padding:12px;border:1px solid rgba(255,255,255,.16);border-radius:8px;background:rgba(255,255,255,.08)}.project-list{display:grid;gap:8px}.project-link{display:grid;grid-template-columns:36px minmax(0,1fr);gap:10px;align-items:center;padding:10px;color:#f8fff9;text-decoration:none;border-radius:8px;border:1px solid transparent}.project-link:hover,.project-link.active{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.16)}.project-link .project-icon{width:36px;height:36px;font-size:13px}.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.main{padding:26px;display:grid;gap:22px;align-content:start}.topbar,.build-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}h2,h3{margin:0}h2{font-size:clamp(28px,4vw,44px);line-height:1}.actions{display:flex;flex-wrap:wrap;gap:10px;justify-content:flex-end}.button,.icon-button{min-height:40px;border-radius:8px;background:var(--charcoal);color:#fff;padding:0 14px;display:inline-flex;align-items:center;justify-content:center;gap:8px;text-decoration:none;font-weight:700}.button.secondary{background:#fff;color:var(--ink);border:1px solid var(--line)}.button.danger{background:var(--rose)}.icon-button{width:40px;padding:0}.grid{display:grid;grid-template-columns:minmax(280px,1.05fr) minmax(320px,1.8fr);gap:18px;align-items:start}.panel,.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow)}.panel{padding:18px;display:grid;gap:16px}.summary{display:grid;grid-template-columns:72px minmax(0,1fr);gap:14px;align-items:center}.summary .project-icon{width:72px;height:72px;font-size:20px}.stats,.build-meta,.permission-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.permission-grid{grid-template-columns:repeat(4,minmax(0,1fr))}.build-meta{grid-template-columns:repeat(4,minmax(0,1fr))}.stat{border:1px solid var(--line);border-radius:8px;padding:12px;min-height:76px}.stat strong{display:block;font-size:24px;line-height:1.1}.stat span,.access-row span{display:block;color:var(--muted);font-size:13px}.form-grid{display:grid;gap:10px}.trio{grid-template-columns:repeat(3,minmax(0,1fr))}.field{display:grid;gap:6px}.label{font-size:12px;font-weight:800;text-transform:uppercase;color:var(--muted)}input,select,textarea{width:100%;border:1px solid var(--line);border-radius:8px;background:#fbfdf9;color:var(--ink);padding:10px 12px;min-height:42px}textarea{min-height:88px;resize:vertical}.dropzone{position:relative;display:grid;place-items:center;min-height:150px;border:2px dashed #9fb2a8;border-radius:8px;background:#fbfff5;text-align:center;padding:18px}.dropzone input{position:absolute;inset:0;opacity:0;cursor:pointer}.build-list,.user-table{display:grid;gap:12px}.card{padding:14px;display:grid;gap:12px}.access-row{display:grid;grid-template-columns:minmax(220px,1.2fr) minmax(180px,.75fr) minmax(240px,1fr) auto;gap:10px;align-items:center;border:1px solid var(--line);border-radius:8px;padding:12px;background:#fbfdf9}.badges{display:flex;flex-wrap:wrap;gap:6px}.badge{display:inline-flex;align-items:center;min-height:26px;border-radius:999px;padding:0 10px;font-size:12px;font-weight:800;background:#edf4ee;color:var(--green)}.badge.qa{color:var(--cyan)}.badge.live{color:var(--rose)}.badge.tag{color:var(--amber)}.code{overflow:hidden;border:1px solid var(--line);border-radius:8px;background:#202825;color:#d8ffe4;padding:12px;font-family:Consolas,monospace;font-size:12px;white-space:nowrap;text-overflow:ellipsis}.split-actions{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:10px}.inline-form{display:flex;gap:8px;align-items:center}.inline-form select{width:auto;min-width:110px}.empty{min-height:240px;display:grid;place-items:center;text-align:center;color:var(--muted)}.login{width:min(420px,100%);margin:12vh auto;padding:22px}.soft-load{position:fixed;right:20px;bottom:20px;z-index:50;width:min(360px,calc(100vw - 36px));display:none;grid-template-columns:34px minmax(0,1fr);gap:12px;align-items:center;background:rgba(31,42,39,.96);color:#f8fff9;border:1px solid rgba(255,255,255,.16);border-radius:8px;box-shadow:var(--shadow);padding:14px}.soft-load.active{display:grid}.soft-load span{color:#b9cbc2;font-size:13px}.spinner{width:28px;height:28px;border:3px solid rgba(255,255,255,.24);border-top-color:var(--lime);border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}@media(max-width:1180px){.access-row{grid-template-columns:1fr 1fr}.permission-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:980px){.shell{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}@media(max-width:640px){.main,.sidebar{padding:18px}.topbar,.build-head{display:grid}.trio,.stats,.build-meta,.permission-grid,.access-row{grid-template-columns:1fr}.button,.inline-form,.inline-form select{width:100%}.inline-form{display:grid}}</style>`;
}

function softLoad() {
  return `<div class="soft-load" id="softLoad" role="status" aria-live="polite" aria-hidden="true"><div class="spinner"></div><div><strong id="softLoadTitle">Working</strong><span id="softLoadStep">Please wait</span></div></div>`;
}

function loaderScript() {
  return `${softLoad()}<script>const softLoad=document.getElementById("softLoad"),softLoadTitle=document.getElementById("softLoadTitle"),softLoadStep=document.getElementById("softLoadStep");function showSoftLoad(s,f){const a=s.filter(Boolean);softLoadTitle.textContent=a[0]||"Working";softLoadStep.textContent=a[1]||"Waiting for the server";softLoad.classList.add("active");f?.querySelectorAll("button").forEach(b=>{b.disabled=true;b.textContent="Working..."})}document.querySelectorAll("form[data-loading-steps]").forEach(f=>f.addEventListener("submit",()=>showSoftLoad(f.dataset.loadingSteps.split("|"),f)));</script>`;
}

function dashboardScript() {
  return `<script>const softLoad=document.getElementById("softLoad"),softLoadTitle=document.getElementById("softLoadTitle"),softLoadStep=document.getElementById("softLoadStep");let timer=null;function showSoftLoad(steps,source){const s=steps.filter(Boolean);clearInterval(timer);let i=0;softLoadTitle.textContent=s[0]||"Working";softLoadStep.textContent=s[1]||"Waiting for the server";softLoad.classList.add("active");source?.querySelectorAll("button,input[type='submit']").forEach(b=>{b.disabled=true;b.dataset.originalText=b.textContent;b.textContent="Working..."});timer=setInterval(()=>{i=(i+1)%s.length;softLoadTitle.textContent=s[i];softLoadStep.textContent="Waiting for the request to complete"},1400)}function updateSoftLoad(t,s){softLoadTitle.textContent=t;softLoadStep.textContent=s||"Waiting for the request to complete"}function restoreForm(f){f.querySelectorAll("button,input[type='submit']").forEach(b=>{b.disabled=false;if(b.dataset.originalText)b.textContent=b.dataset.originalText})}async function sha256Hex(file){const buf=await file.arrayBuffer();const hash=await crypto.subtle.digest("SHA-256",buf);return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,"0")).join("")}function payload(form){const d=new FormData(form);return{version:d.get("version")||"",channel:d.get("channel")||"dev",tag:d.get("tag")||"",changelog:d.get("changelog")||""}}async function responseText(response){try{return await response.text()}catch{return ""}}async function uploadBuild(form){const files=Array.from(form.querySelector("input[type='file']").files||[]);if(!files.length)return;showSoftLoad(form.dataset.loadingSteps.split("|"),form);try{updateSoftLoad("Preparing R2 upload","Requesting signed URLs");const init=await fetch(form.dataset.initUrl,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...payload(form),files:files.map(f=>({name:f.name,size:f.size,content_type:f.type||"application/octet-stream"}))})});if(!init.ok)throw new Error("Init failed: "+init.status+" "+await responseText(init));const session=await init.json();const uploaded=[];for(let i=0;i<files.length;i++){const file=files[i],target=session.uploads[i];updateSoftLoad("Hashing "+(i+1)+"/"+files.length,file.name);const hash=await sha256Hex(file);updateSoftLoad("Uploading "+(i+1)+"/"+files.length,file.name);let put;try{put=await fetch(target.upload_url,{method:"PUT",headers:{"Content-Type":target.content_type},body:file})}catch(error){throw new Error("R2 PUT request was blocked or could not connect. Check R2 CORS AllowedOrigins and the Worker domain. "+error.message)}if(!put.ok)throw new Error("R2 PUT failed for "+file.name+": "+put.status+" "+await responseText(put));uploaded.push({name:file.name,size:file.size,hash,content_type:target.content_type,object_path:target.object_path})}updateSoftLoad("Saving build","Writing manifest to D1");const done=await fetch(form.dataset.completeBase+"/"+session.build_id+"/complete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...payload(form),version:session.version,files:uploaded})});if(!done.ok)throw new Error("Complete failed: "+done.status+" "+await responseText(done));location.href=form.dataset.returnUrl}catch(e){clearInterval(timer);updateSoftLoad("Upload failed",e.message);restoreForm(form)}}document.querySelectorAll("form[data-direct-upload='true']").forEach(f=>f.addEventListener("submit",e=>{e.preventDefault();uploadBuild(f)}));document.querySelectorAll("form[data-loading-steps]").forEach(f=>f.addEventListener("submit",e=>{if(f.dataset.directUpload==="true")return;if(f.dataset.confirm&&!confirm(f.dataset.confirm)){e.preventDefault();return}showSoftLoad(f.dataset.loadingSteps.split("|"),f)}));document.querySelectorAll("a[data-loading-steps]").forEach(a=>a.addEventListener("click",()=>showSoftLoad(a.dataset.loadingSteps.split("|"),a)));</script>`;
}
