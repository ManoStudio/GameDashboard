const CHANNELS = ["dev", "qa", "live"];
const USER_ROLES = ["admin", "dev", "QA", "viewer"];
const PASSWORD_HASH_ITERATIONS = 100000;

const encoder = new TextEncoder();

export default {
  async fetch(request, env) {
    try {
      await ensureSchema(env);
      await bootstrapAdmin(env);
      const url = new URL(request.url);
      const user = await currentUser(request, env);
      const route = await dispatch(request, env, url, user);
      return route || notFound();
    } catch (error) {
      return html(`<h1>Server Error</h1><pre>${escapeHtml(error.stack || error.message)}</pre>`, 500);
    }
  },
};

async function ensureSchema(env) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      role TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      icon TEXT NOT NULL,
      bundle_id TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS builds (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      version TEXT NOT NULL,
      channel TEXT NOT NULL,
      tag TEXT,
      changelog TEXT,
      status TEXT NOT NULL,
      file_count INTEGER NOT NULL,
      total_size INTEGER NOT NULL,
      storage_path TEXT NOT NULL,
      manifest_path TEXT NOT NULL,
      manifest_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,
    "CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_builds_project_created ON builds(project_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email)",
  ];

  for (const statement of statements) {
    await env.DB.prepare(statement).run();
  }
}

async function dispatch(request, env, url, user) {
  const path = url.pathname;
  const method = request.method;

  if (path === "/login" && method === "GET") return loginPage();
  if (path === "/login" && method === "POST") return login(request, env);
  if (path === "/logout" && method === "POST") return logout(request, env);
  if (path === "/api/auth/login" && method === "POST") return loginJson(request, env);
  if (path === "/api/auth/logout" && method === "POST") return logoutJson(request, env);
  if (path === "/api/me" && method === "GET") return requireLogin(user, true) || json({ user: describeUser(user) });
  if (path === "/api/launcher/latest" && method === "GET") return launcherLatest(request, env);
  if (path === "/" && method === "GET") return requireLogin(user) || dashboard(request, env, user);

  if (path === "/projects" && method === "POST") return requireRole(user, "admin") || createProject(request, env);
  const projectUpdate = path.match(/^\/projects\/([^/]+)$/);
  if (projectUpdate && method === "POST") return requireRole(user, "admin") || updateProject(request, env, projectUpdate[1]);
  const projectDelete = path.match(/^\/projects\/([^/]+)\/delete$/);
  if (projectDelete && method === "POST") return requireRole(user, "admin") || deleteProject(request, env, projectDelete[1]);

  if (path === "/users" && method === "POST") return requireRole(user, "admin") || upsertUser(request, env);
  const userRole = path.match(/^\/users\/([^/]+)\/role$/);
  if (userRole && method === "POST") return requireRole(user, "admin") || updateUserRole(request, env, user, decodeURIComponent(userRole[1]));
  const userPassword = path.match(/^\/users\/([^/]+)\/password$/);
  if (userPassword && method === "POST") return requireRole(user, "admin") || resetUserPassword(request, env, decodeURIComponent(userPassword[1]));
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
  const completeUpload = path.match(/^\/api\/projects\/([^/]+)\/uploads\/([^/]+)\/complete$/);
  if (completeUpload && method === "POST") return requireRole(user, "admin", "dev", true) || completeUploadSession(request, env, user, completeUpload[1], completeUpload[2]);

  const artifact = path.match(/^\/api\/artifacts\/(.+)$/);
  if (artifact && method === "GET") return downloadArtifact(request, env, user, decodeURIComponent(artifact[1]));

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

  return null;
}

async function bootstrapAdmin(env) {
  if (!env.ADMIN_EMAIL || !env.ADMIN_PASSWORD) return;
  const email = env.ADMIN_EMAIL.trim().toLowerCase();
  const existing = await env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(email).first();
  if (existing) return;
  const now = nowIso();
  await env.DB.prepare(
    "INSERT INTO users (email, role, password_hash, created_at, updated_at) VALUES (?, 'admin', ?, ?, ?)"
  ).bind(email, await hashPassword(env.ADMIN_PASSWORD), now, now).run();
}

async function currentUser(request, env) {
  const tokenUser = apiTokenUser(request, env);
  if (tokenUser) return tokenUser;
  const token = cookie(request, "sid");
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const session = await env.DB.prepare(
    "SELECT sessions.email, users.role FROM sessions JOIN users ON users.email = sessions.email WHERE token_hash = ? AND expires_at > ?"
  ).bind(tokenHash, nowIso()).first();
  return session ? { email: session.email, role: session.role } : null;
}

function describeUser(user) {
  if (!user) return null;
  return {
    email: user.email,
    role: user.role,
    visible_channels: visibleChannelsForRole(user.role),
    runtime_environments: runtimeEnvironmentsForRole(user.role),
  };
}

function apiTokenUser(request, env) {
  const expected = env.DASHBOARD_API_TOKEN;
  const header = request.headers.get("Authorization") || "";
  if (!expected || header !== `Bearer ${expected}`) return null;
  return { email: "api-token", role: "admin" };
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
  return html(renderDashboard({ user, projects, selected, builds, users }));
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
    visibleProjects.push(project);
  }
  return visibleProjects;
}

async function getProject(env, id, user = null) {
  const project = await env.DB.prepare("SELECT * FROM projects WHERE id = ?").bind(id).first();
  return canAccessProject(user, project) ? project : null;
}

async function listBuilds(env, projectId, user = null, baseUrl = "") {
  const project = await getProject(env, projectId, user);
  if (!project) return [];
  const { results } = await env.DB.prepare("SELECT * FROM builds WHERE project_id = ? ORDER BY created_at DESC").bind(projectId).all();
  const visibleChannels = new Set(visibleChannelsForRole(user?.role));
  return Promise.all((results || []).filter(row => visibleChannels.has(row.channel)).map(row => rowToBuild(env, row, baseUrl)));
}

async function listUsers(env) {
  const { results } = await env.DB.prepare("SELECT email, role, created_at, updated_at FROM users ORDER BY email").all();
  return results || [];
}

async function createProject(request, env) {
  const form = await request.formData();
  const id = `project-${crypto.randomUUID().slice(0, 8)}`;
  const now = nowIso();
  await env.DB.prepare(
    "INSERT INTO projects (id, name, icon, bundle_id, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, field(form, "name"), field(form, "icon") || "GM", field(form, "bundle_id"), field(form, "role") || "viewer", now, now).run();
  return redirect(`/?project=${id}`);
}

async function updateProject(request, env, id) {
  const form = await request.formData();
  await env.DB.prepare("UPDATE projects SET name = ?, icon = ?, bundle_id = ?, role = ?, updated_at = ? WHERE id = ?")
    .bind(field(form, "name"), field(form, "icon") || "GM", field(form, "bundle_id"), field(form, "role") || "viewer", nowIso(), id)
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
  await env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(id).run();
  return builds.length;
}

async function upsertUser(request, env) {
  const form = await request.formData();
  const email = field(form, "email").toLowerCase();
  const role = USER_ROLES.includes(field(form, "role")) ? field(form, "role") : "viewer";
  const password = field(form, "password");
  const existing = await env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(email).first();
  const now = nowIso();
  if (!existing && !password) return redirect("/");
  if (existing && !password) {
    await env.DB.prepare("UPDATE users SET role = ?, updated_at = ? WHERE email = ?").bind(role, now, email).run();
  } else {
    await env.DB.prepare(
      "INSERT INTO users (email, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(email) DO UPDATE SET role = excluded.role, password_hash = excluded.password_hash, updated_at = excluded.updated_at"
    ).bind(email, role, await hashPassword(password), now, now).run();
  }
  return redirect("/");
}

async function updateUserRole(request, env, current, email) {
  const form = await request.formData();
  const role = USER_ROLES.includes(field(form, "role")) ? field(form, "role") : "viewer";
  if (email === current.email && role !== "admin") return redirect("/");
  await env.DB.prepare("UPDATE users SET role = ?, updated_at = ? WHERE email = ?").bind(role, nowIso(), email).run();
  return redirect("/");
}

async function resetUserPassword(request, env, email) {
  const form = await request.formData();
  const password = field(form, "password");
  if (!password) return redirect("/");
  await env.DB.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE email = ?")
    .bind(await hashPassword(password), nowIso(), email)
    .run();
  await env.DB.prepare("DELETE FROM sessions WHERE email = ?").bind(email).run();
  return redirect("/");
}

async function deleteUser(request, env, current, email) {
  if (email === current.email) return redirect("/");
  await env.DB.prepare("DELETE FROM sessions WHERE email = ?").bind(email).run();
  await env.DB.prepare("DELETE FROM users WHERE email = ?").bind(email).run();
  return redirect("/");
}

async function initUploadSession(request, env, user, projectId) {
  const missing = ["R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET_NAME"].filter(key => !env[key]);
  if (missing.length) return json({ error: `missing R2 config: ${missing.join(", ")}` }, 500);

  const payload = await request.json();
  const channel = payload.channel || "dev";
  if (!CHANNELS.includes(channel)) return json({ error: "invalid channel" }, 400);
  if (!canAssign(user.role, channel)) return json({ error: "forbidden" }, 403);
  const files = payload.files || [];
  if (!files.length) return json({ error: "files are required" }, 400);
  const buildId = `build-${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
  const version = payload.version || await nextVersion(env, projectId);
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

async function completeUploadSession(request, env, user, projectId, buildId) {
  const baseUrl = new URL(request.url).origin;
  const payload = await request.json();
  const channel = payload.channel || "dev";
  if (!CHANNELS.includes(channel)) return json({ error: "invalid channel" }, 400);
  if (!canAssign(user.role, channel)) return json({ error: "forbidden" }, 403);
  const files = payload.files || [];
  if (!files.length) return json({ error: "files are required" }, 400);
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
  const build = await saveBuild(env, projectId, buildId, payload, manifest, baseUrl);
  return json(build, 201);
}

async function saveBuild(env, projectId, buildId, payload, manifest, baseUrl = "") {
  const now = nowIso();
  const version = payload.version || await nextVersion(env, projectId);
  const channel = CHANNELS.includes(payload.channel) ? payload.channel : "dev";
  await env.DB.prepare(
    "INSERT INTO builds (id, project_id, version, channel, tag, changelog, status, file_count, total_size, storage_path, manifest_path, manifest_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'assigned', ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    buildId,
    projectId,
    version,
    channel,
    payload.tag || "",
    payload.changelog || "Manual upload",
    manifest.file_count,
    manifest.total_size,
    `r2://${env.R2_BUCKET_NAME}/builds/${projectId}/${buildId}/files`,
    `r2://${env.R2_BUCKET_NAME}/builds/${projectId}/${buildId}/manifest.json`,
    JSON.stringify(manifest),
    now,
    now
  ).run();
  return rowToBuild(env, await env.DB.prepare("SELECT * FROM builds WHERE id = ?").bind(buildId).first(), baseUrl);
}

async function updateBuildChannel(request, env, user, buildId) {
  const payload = request.headers.get("content-type")?.includes("application/json")
    ? await request.json()
    : Object.fromEntries(await request.formData());
  const channel = payload.channel || "dev";
  if (!CHANNELS.includes(channel)) return json({ error: "invalid channel" }, 400);
  if (!canAssign(user.role, channel)) return json({ error: "forbidden" }, 403);
  await env.DB.prepare("UPDATE builds SET channel = ?, status = 'assigned', updated_at = ? WHERE id = ?").bind(channel, nowIso(), buildId).run();
  const build = await env.DB.prepare("SELECT project_id FROM builds WHERE id = ?").bind(buildId).first();
  return request.url.includes("/api/") ? json({ id: buildId, channel }) : redirect(`/?project=${build?.project_id || ""}`);
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
  if (!project || !visibleChannelsForRole(user?.role).includes(build.channel)) return json({ error: "build not found" }, 404);
  return json(await manifestWithDownloadUrls(env, JSON.parse(build.manifest_json), new URL(request.url).origin));
}

async function launcherLatest(request, env) {
  const url = new URL(request.url);
  const channel = CHANNELS.includes(url.searchParams.get("channel")) ? url.searchParams.get("channel") : "live";
  const currentVersion = String(url.searchParams.get("current_version") || "").trim();
  const projectId = url.searchParams.get("project_id") || env.LAUNCHER_PROJECT_ID || "";
  const bundleId = url.searchParams.get("bundle_id") || env.LAUNCHER_BUNDLE_ID || "";
  let row = null;

  if (projectId) {
    row = await env.DB.prepare(
      "SELECT * FROM builds WHERE project_id = ? AND channel = ? ORDER BY created_at DESC LIMIT 1"
    ).bind(projectId, channel).first();
  } else if (bundleId) {
    row = await env.DB.prepare(
      "SELECT builds.* FROM builds JOIN projects ON projects.id = builds.project_id WHERE projects.bundle_id = ? AND builds.channel = ? ORDER BY builds.created_at DESC LIMIT 1"
    ).bind(bundleId, channel).first();
  } else {
    row = await env.DB.prepare(
      "SELECT builds.* FROM builds JOIN projects ON projects.id = builds.project_id WHERE builds.channel = ? AND (lower(projects.name) LIKE '%launcher%' OR lower(projects.bundle_id) LIKE '%launcher%') ORDER BY builds.created_at DESC LIMIT 1"
    ).bind(channel).first();
    if (!row) {
      row = await env.DB.prepare(
        "SELECT * FROM builds WHERE channel = ? ORDER BY created_at DESC LIMIT 1"
      ).bind(channel).first();
    }
  }

  if (!row) return json({ error: "launcher build not found", channel }, 404);

  const build = await rowToBuild(env, row, url.origin);
  const files = build?.manifest?.files || [];
  const artifact =
    files.find(file => /\.(exe|msi|zip|dmg|pkg|appimage)$/i.test(String(file.path || ""))) ||
    files[0] ||
    null;
  const downloadUrl = artifact?.download_url || artifact?.storage_url || "";
  const hasUpdate = currentVersion ? compareVersions(build.version, currentVersion) > 0 : true;

  return json({
    has_update: hasUpdate,
    is_mandatory: false,
    version: build.version,
    download_url: downloadUrl,
    notes: build.changelog || "No release notes.",
  });
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

async function downloadArtifact(request, env, user, key) {
  if (!key.startsWith("builds/")) return json({ error: "invalid object path" }, 400);
  const url = new URL(request.url);
  const signed = await validArtifactSignature(env, key, url.searchParams);
  if (!user && !signed) return json({ error: "unauthorized" }, 401);

  const object = await env.BUILDS_BUCKET.get(key);
  if (!object) return json({ error: "artifact not found" }, 404);

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Cache-Control", "private, max-age=300");
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/octet-stream");
  return new Response(object.body, { headers });
}

async function validArtifactSignature(env, key, params) {
  const expires = Number(params.get("expires") || 0);
  const signature = params.get("signature") || "";
  if (!expires || !signature || expires < Math.floor(Date.now() / 1000)) return false;
  const expected = await hmacHex(encoder.encode(env.R2_SECRET_ACCESS_KEY), `${key}.${expires}`);
  return signature === expected;
}

async function nextVersion(env, projectId) {
  const latest = await env.DB.prepare("SELECT version FROM builds WHERE project_id = ? ORDER BY created_at DESC LIMIT 1").bind(projectId).first();
  if (!latest) return "1.0.0";
  const parts = latest.version.split(".").map(part => Number(part));
  return parts.length === 3 && parts.every(Number.isInteger) ? `${parts[0]}.${parts[1]}.${parts[2] + 1}` : `${latest.version}.1`;
}

async function rowToBuild(env, row, baseUrl = "") {
  if (!row) return null;
  return {
    ...row,
    manifest: row.manifest_json ? await manifestWithDownloadUrls(env, JSON.parse(row.manifest_json), baseUrl) : null,
  };
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
  const requiredRole = project.role || "viewer";
  const effectiveRole = user?.role || "viewer";
  return roleRank(effectiveRole) >= roleRank(requiredRole);
}

function visibleChannelsForRole(role) {
  if (role === "admin" || role === "dev") return ["dev", "qa", "live"];
  if (role === "QA") return ["qa", "live"];
  return ["live"];
}

function runtimeEnvironmentsForRole(role) {
  return role === "viewer" || !role ? ["production"] : ["dev", "staging", "production"];
}

function canAssign(role, channel) {
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

async function presignGet(env, key) {
  return presignR2Url(env, "GET", key, 3600, {
    canonicalHeaders: `host:${r2Host(env)}\n`,
    signedHeaders: "host",
  });
}

async function presignR2Url(env, method, key, expires, options) {
  const host = r2Host(env);
  const path = r2Path(env, key);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/auto/s3/aws4_request`;
  const credential = `${env.R2_ACCESS_KEY_ID}/${credentialScope}`;
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
  const signingKey = await signatureKey(env.R2_SECRET_ACCESS_KEY, dateStamp, "auto", "s3");
  const signature = await hmacHex(signingKey, stringToSign);
  return `https://${host}${path}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

function r2Host(env) {
  return `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
}

function r2Path(env, key) {
  return `/${env.R2_BUCKET_NAME}/${encodeURIComponent(key).replaceAll("%2F", "/")}`;
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
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8" } });
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
  return html(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>${style()}</head><body><main class="login panel"><div class="brand"><div class="mark">BP</div><div><h1>Build Producer</h1><p>Cloudflare dashboard</p></div></div>${error ? `<div class="alert">${escapeHtml(error)}</div>` : ""}<form method="post" class="form-grid" data-loading-steps="Checking credentials|Creating session|Opening dashboard"><label class="field"><span class="label">Email</span><input name="email" type="email" required autofocus></label><label class="field"><span class="label">Password</span><input name="password" type="password" required></label><button class="button">Login</button></form></main>${loaderScript()}</body></html>`);
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

function projectManagement(user, project, builds, latest) {
  return `<div class="summary"><div class="project-icon">${escapeHtml(project.icon.slice(0, 2).toUpperCase())}</div><div><h3>Project Management</h3><p>role: ${escapeHtml(project.role)}</p></div></div>${user.role === "admin" ? `<form class="form-grid" method="post" action="/projects/${project.id}" data-loading-steps="Saving project|Updating D1|Refreshing dashboard"><label class="field"><span class="label">Project name</span><input name="name" value="${escapeHtml(project.name)}" required></label><label class="field"><span class="label">Icon</span><input name="icon" value="${escapeHtml(project.icon)}" maxlength="4"></label><label class="field"><span class="label">Bundle ID</span><input name="bundle_id" value="${escapeHtml(project.bundle_id)}" required></label><label class="field"><span class="label">Access role</span><select name="role">${["viewer", "QA", "dev", "admin"].map(role => `<option ${project.role === role ? "selected" : ""}>${role}</option>`).join("")}</select></label><button class="button">Save Project</button></form><form method="post" action="/projects/${project.id}/delete" data-confirm="Delete this project and all builds?" data-loading-steps="Deleting R2 files|Removing project|Refreshing dashboard"><button class="button danger">Delete Project</button></form>` : ""}<div class="stats"><div class="stat"><strong>${builds.length}</strong><span>builds</span></div><div class="stat"><strong>${latest?.channel || "-"}</strong><span>latest channel</span></div><div class="stat"><strong>${latest?.version || "-"}</strong><span>version</span></div></div>`;
}

function uploadPanel(user, project) {
  return `<div class="panel"><h3>Build Upload</h3><form class="form-grid" data-direct-upload="true" data-init-url="/api/projects/${project.id}/uploads/init" data-complete-base="/api/projects/${project.id}/uploads" data-return-url="/?project=${project.id}" data-loading-steps="Preparing R2 upload|Hashing files|Uploading files|Saving build"><label class="dropzone"><input type="file" name="build" multiple required><span><strong>Drop build zip here</strong><span>Files upload directly to Cloudflare R2.</span></span></label><div class="form-grid trio"><label class="field"><span class="label">Version</span><input name="version" placeholder="auto"></label><label class="field"><span class="label">Channel</span><select name="channel">${CHANNELS.filter(c => user.role === "admin" || c !== "live").map(c => `<option>${c}</option>`).join("")}</select></label><label class="field"><span class="label">Tag</span><input name="tag" placeholder="hotfix / stable"></label></div><label class="field"><span class="label">Changelog</span><textarea name="changelog"></textarea></label><button class="button">Upload Build</button></form></div>`;
}

function userAccess(users, currentUser) {
  return `<section class="panel"><div class="build-head"><div><h3>Access Control</h3><p>Manage dashboard users, roles, and password resets.</p></div></div>${permissionMatrix()}<form class="form-grid" method="post" action="/users" data-loading-steps="Creating user|Hashing password|Refreshing access list"><h3>Create User</h3><div class="form-grid trio"><label class="field"><span class="label">Email</span><input name="email" type="email" required></label><label class="field"><span class="label">Password</span><input name="password" type="password" required></label><label class="field"><span class="label">Role</span><select name="role">${USER_ROLES.map(role => `<option>${role}</option>`).join("")}</select></label></div><button class="button">Create User</button></form><div class="user-table">${users.map(u => userRow(u, currentUser)).join("")}</div></section>`;
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
  return `<article class="access-row"><div><strong>${email}</strong><span>role: ${escapeHtml(accessUser.role)}${isSelf ? " / current user" : ""}</span></div><form class="inline-form" method="post" action="/users/${encodedEmail}/role" data-loading-steps="Updating role|Refreshing access list"><select name="role">${USER_ROLES.map(role => `<option ${accessUser.role === role ? "selected" : ""} ${isSelf && role !== "admin" ? "disabled" : ""}>${role}</option>`).join("")}</select><button class="button secondary">Role</button></form><form class="inline-form" method="post" action="/users/${encodedEmail}/password" data-loading-steps="Resetting password|Clearing sessions"><input name="password" type="password" placeholder="new password" required><button class="button secondary">Reset</button></form>${isSelf ? `<button class="button secondary" disabled>Protected</button>` : `<form method="post" action="/users/${encodedEmail}/delete" data-confirm="Delete ${email}?" data-loading-steps="Deleting user|Clearing sessions|Refreshing access list"><button class="button danger">Delete</button></form>`}</article>`;
}

function buildHistory(user, project, builds) {
  return `<section class="panel"><div class="build-head"><div><h3>Build History</h3><p>Rollback promotes a selected build back to live.</p></div><div class="code">POST /api/projects/${project.id}/uploads/init</div></div>${builds.length ? `<div class="build-list">${builds.map(build => buildCard(user, build)).join("")}</div>` : `<div class="empty">No builds yet.</div>`}</section>`;
}

function buildCard(user, build) {
  const channels = CHANNELS.filter(channel => canAssign(user.role, channel));
  return `<article class="card"><div class="build-head"><div><h3>Version ${escapeHtml(build.version)}</h3><p>${escapeHtml(build.created_at)}</p></div><div class="badges"><span class="badge ${escapeHtml(build.channel)}">${escapeHtml(build.channel)}</span>${build.tag ? `<span class="badge tag">${escapeHtml(build.tag)}</span>` : ""}<span class="badge">${escapeHtml(build.status)}</span></div></div><div class="build-meta"><div class="stat"><strong>${build.file_count}</strong><span>files</span></div><div class="stat"><strong>${(build.total_size / 1048576).toFixed(2)}</strong><span>MB</span></div><div class="stat"><strong>${escapeHtml(build.channel)}</strong><span>channel</span></div><div class="stat"><strong>${escapeHtml(build.tag || "-")}</strong><span>tag</span></div></div><p>${escapeHtml(build.changelog || "")}</p><div class="code">${escapeHtml(build.storage_path)} | ${escapeHtml(build.manifest_path)}</div><div class="split-actions">${channels.length ? `<form class="inline-form" method="post" action="/builds/${build.id}/channel" data-loading-steps="Assigning channel|Updating build status|Refreshing history"><select name="channel">${channels.map(c => `<option ${build.channel === c ? "selected" : ""}>${c}</option>`).join("")}</select><button class="icon-button">&rarr;</button></form>` : ""}<div class="actions"><a class="button secondary" href="/builds/${build.id}/manifest" data-loading-steps="Opening manifest|Loading build metadata">Manifest</a>${user.role === "admin" ? `<form method="post" action="/builds/${build.id}/rollback" data-loading-steps="Starting rollback|Promoting build to live|Refreshing history"><button class="button secondary">Rollback</button></form>` : ""}${["admin", "dev"].includes(user.role) ? `<form method="post" action="/builds/${build.id}/delete" data-confirm="Delete build version ${escapeHtml(build.version)}?" data-loading-steps="Deleting build files|Removing build metadata|Refreshing history"><button class="button danger">Delete Build</button></form>` : ""}</div></div></article>`;
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
