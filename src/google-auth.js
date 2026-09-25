const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
const GOOGLE_KEYS = "https://www.googleapis.com/oauth2/v3/certs";
const encoder = new TextEncoder();

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return base64url(bytes);
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeBase64url(value) {
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function hash(value) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)))].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });
const redirect = (location, headers = {}) => new Response(null, { status: 302, headers: { Location: location, "Cache-Control": "no-store", ...headers } });

function configReady(env) {
  return Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET && env.GOOGLE_REDIRECT_URI);
}

function validLoopback(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" && url.hostname === "127.0.0.1" && /^\/callback\/?$/.test(url.pathname) && !url.username && !url.password && !url.search && !url.hash && Number(url.port) > 0;
  } catch {
    return false;
  }
}

export async function startGoogle(request, env) {
  if (!configReady(env)) return json({ error: "Google sign-in is not configured." }, 503);
  const url = new URL(request.url);
  const mode = url.searchParams.get("mode") === "desktop" ? "desktop" : "web";
  if (mode === "web" && url.origin !== new URL(env.GOOGLE_REDIRECT_URI).origin) {
    return redirect(new URL("/api/auth/google/start", env.GOOGLE_REDIRECT_URI).toString());
  }
  const loopback = url.searchParams.get("redirect_uri");
  const challenge = url.searchParams.get("code_challenge");
  const clientState = url.searchParams.get("client_state");
  if (mode === "desktop" && (!validLoopback(loopback) || !/^[A-Za-z0-9_-]{43}$/.test(challenge || "") || !/^[A-Za-z0-9_-]{32,128}$/.test(clientState || ""))) {
    return json({ error: "Invalid desktop sign-in request." }, 400);
  }
  const now = new Date().toISOString();
  await env.DB.prepare("DELETE FROM oauth_flows WHERE expires_at < ?").bind(now).run();
  await env.DB.prepare("DELETE FROM desktop_auth_codes WHERE expires_at < ?").bind(now).run();
  const state = randomToken();
  const nonce = randomToken();
  const expires = new Date(Date.now() + 5 * 60_000).toISOString();
  await env.DB.prepare("INSERT INTO oauth_flows (state_hash, nonce, mode, redirect_uri, client_state, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(await hash(state), nonce, mode, mode === "desktop" ? loopback : null, mode === "desktop" ? clientState : null, mode === "desktop" ? challenge : null, expires).run();
  const google = new URL(GOOGLE_AUTH);
  google.search = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: env.GOOGLE_REDIRECT_URI, response_type: "code", scope: "openid email", state, nonce, prompt: "select_account" }).toString();
  return redirect(google.toString(), mode === "web" ? { "Set-Cookie": `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/google/callback; Max-Age=300` } : {});
}

function cookie(request, name) {
  const part = (request.headers.get("Cookie") || "").split(";").find(item => item.trim().startsWith(`${name}=`));
  return part?.trim().slice(name.length + 1) || "";
}

async function verifiedIdentity(idToken, env, nonce) {
  const parts = String(idToken || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid Google identity token.");
  const header = JSON.parse(new TextDecoder().decode(decodeBase64url(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(decodeBase64url(parts[1])));
  if (header.alg !== "RS256" || !header.kid || claims.iss !== "https://accounts.google.com" && claims.iss !== "accounts.google.com" || claims.aud !== env.GOOGLE_CLIENT_ID || claims.exp <= Date.now() / 1000 || claims.iat > Date.now() / 1000 + 60 || claims.nonce !== nonce || claims.email_verified !== true || !claims.sub || !claims.email) {
    throw new Error("Google identity could not be verified.");
  }
  const response = await fetch(GOOGLE_KEYS);
  if (!response.ok) throw new Error("Google signing keys unavailable.");
  const { keys } = await response.json();
  const jwk = keys.find(key => key.kid === header.kid && key.kty === "RSA" && key.use === "sig");
  if (!jwk) throw new Error("Google signing key not found.");
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decodeBase64url(parts[2]), encoder.encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error("Invalid Google token signature.");
  return { email: String(claims.email).toLowerCase(), sub: String(claims.sub) };
}

export async function googleCallback(request, env) {
  const url = new URL(request.url);
  const state = url.searchParams.get("state") || "";
  if (!state || !configReady(env)) return json({ error: "Sign-in session expired." }, 400);
  const flow = await env.DB.prepare("DELETE FROM oauth_flows WHERE state_hash = ? AND expires_at > ? RETURNING *").bind(await hash(state), new Date().toISOString()).first();
  if (!flow) return json({ error: "Sign-in session expired or already used." }, 400);
  if (flow.mode === "web" && cookie(request, "oauth_state") !== state) return json({ error: "Sign-in browser session did not match." }, 400);
  const fail = message => {
    if (flow.mode === "desktop") {
      const target = new URL(flow.redirect_uri);
      target.searchParams.set("error", message);
      target.searchParams.set("state", flow.client_state);
      return redirect(target.toString());
    }
    return redirect(`/login?error=${encodeURIComponent(message)}`, { "Set-Cookie": "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/google/callback; Max-Age=0" });
  };
  const code = url.searchParams.get("code");
  if (!code || url.searchParams.has("error")) return fail("Google sign-in was cancelled.");
  try {
    const tokenResponse = await fetch(GOOGLE_TOKEN, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: env.GOOGLE_REDIRECT_URI, grant_type: "authorization_code" }) });
    if (!tokenResponse.ok) return fail("Google sign-in could not be completed.");
    const tokens = await tokenResponse.json();
    const identity = await verifiedIdentity(tokens.id_token, env, flow.nonce);
    const user = await env.DB.prepare("SELECT email, role, google_sub FROM users WHERE email = ?").bind(identity.email).first();
    if (!user || user.google_sub && user.google_sub !== identity.sub) return fail("This Google account has not been granted Dashboard access.");
    if (!user.google_sub) await env.DB.prepare("UPDATE users SET google_sub = ?, updated_at = ? WHERE email = ? AND google_sub IS NULL").bind(identity.sub, new Date().toISOString(), user.email).run();
    if (flow.mode === "desktop") {
      const ticket = randomToken();
      await env.DB.prepare("INSERT INTO desktop_auth_codes (code_hash, email, code_challenge, expires_at) VALUES (?, ?, ?, ?)").bind(await hash(ticket), user.email, flow.code_challenge, new Date(Date.now() + 90_000).toISOString()).run();
      const target = new URL(flow.redirect_uri);
      target.searchParams.set("code", ticket);
      target.searchParams.set("state", flow.client_state);
      return redirect(target.toString());
    }
    const session = await issueSession(env, user);
    const response = redirect("/", { "Set-Cookie": session.cookie });
    response.headers.append("Set-Cookie", "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/google/callback; Max-Age=0");
    return response;
  } catch {
    return fail("Google sign-in could not be verified.");
  }
}

async function issueSession(env, user) {
  const token = randomToken();
  const now = new Date();
  await env.DB.prepare("INSERT INTO sessions (token_hash, email, expires_at, created_at) VALUES (?, ?, ?, ?)")
    .bind(await hash(token), user.email, new Date(now.getTime() + 7 * 86400_000).toISOString(), now.toISOString()).run();
  return { user: { email: user.email, role: user.role }, cookie: `sid=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800` };
}

export async function exchangeDesktop(request, env) {
  let payload;
  try { payload = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
  const code = String(payload.code || "");
  const verifier = String(payload.code_verifier || "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(code) || !/^[A-Za-z0-9_-]{43}$/.test(verifier)) return json({ error: "Invalid exchange code." }, 400);
  const ticket = await env.DB.prepare("DELETE FROM desktop_auth_codes WHERE code_hash = ? AND expires_at > ? RETURNING *").bind(await hash(code), new Date().toISOString()).first();
  if (!ticket) return json({ error: "Sign-in code expired or already used." }, 401);
  if (base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(verifier)))) !== ticket.code_challenge) return json({ error: "Sign-in verification failed." }, 401);
  const user = await env.DB.prepare("SELECT email, role FROM users WHERE email = ? AND google_sub IS NOT NULL").bind(ticket.email).first();
  if (!user) return json({ error: "Dashboard access was removed." }, 403);
  const session = await issueSession(env, user);
  return json({ user: session.user }, 200, { "Set-Cookie": session.cookie });
}
