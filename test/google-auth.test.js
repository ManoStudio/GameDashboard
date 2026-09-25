import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, webcrypto } from "node:crypto";
import { startGoogle, googleCallback, exchangeDesktop } from "../src/google-auth.js";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

function database(users) {
  const flows = new Map();
  const tickets = new Map();
  const sessions = new Map();
  return {
    flows, tickets, sessions, users,
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async run() {
              if (sql.startsWith("DELETE FROM oauth_flows WHERE expires_at")) { for (const [key, flow] of flows) if (flow.expires_at < args[0]) flows.delete(key); }
              else if (sql.startsWith("DELETE FROM desktop_auth_codes WHERE expires_at")) { for (const [key, ticket] of tickets) if (ticket.expires_at < args[0]) tickets.delete(key); }
              else if (sql.startsWith("INSERT INTO oauth_flows")) flows.set(args[0], { state_hash: args[0], nonce: args[1], mode: args[2], redirect_uri: args[3], client_state: args[4], code_challenge: args[5], expires_at: args[6] });
              else if (sql.startsWith("INSERT INTO desktop_auth_codes")) tickets.set(args[0], { code_hash: args[0], email: args[1], code_challenge: args[2], expires_at: args[3] });
              else if (sql.startsWith("UPDATE users SET google_sub")) users.get(args[2]).google_sub = args[0];
              else if (sql.startsWith("INSERT INTO sessions")) sessions.set(args[0], { email: args[1], expires_at: args[2] });
              else throw new Error(`Unexpected SQL: ${sql}`);
            },
            async first() {
              if (sql.startsWith("DELETE FROM oauth_flows")) { const row = flows.get(args[0]); flows.delete(args[0]); return row?.expires_at > args[1] ? row : null; }
              if (sql.startsWith("DELETE FROM desktop_auth_codes")) { const row = tickets.get(args[0]); tickets.delete(args[0]); return row?.expires_at > args[1] ? row : null; }
              if (sql.startsWith("SELECT email, role, google_sub")) return users.get(args[0]) || null;
              if (sql.startsWith("SELECT email, role FROM users")) return users.get(args[0]) || null;
              throw new Error(`Unexpected SQL: ${sql}`);
            },
          };
        },
      };
    },
  };
}

test("desktop Google flow issues one-use session with Dashboard role", async () => {
  const DB = database(new Map([["qa@example.com", { email: "qa@example.com", role: "QA", google_sub: null }]]));
  const env = { DB, GOOGLE_CLIENT_ID: "client-id", GOOGLE_CLIENT_SECRET: "secret", GOOGLE_REDIRECT_URI: "https://dashboard.example/api/auth/google/callback" };
  const verifier = "v".repeat(43);
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const clientState = "s".repeat(43);
  const url = new URL("https://dashboard.example/api/auth/google/start");
  url.search = new URLSearchParams({ mode: "desktop", redirect_uri: "http://127.0.0.1:43120/callback", code_challenge: challenge, client_state: clientState }).toString();
  const started = await startGoogle(new Request(url), env);
  assert.equal(started.status, 302);
  const googleUrl = new URL(started.headers.get("Location"));
  assert.equal(googleUrl.searchParams.get("client_id"), env.GOOGLE_CLIENT_ID);
  const state = googleUrl.searchParams.get("state");
  const nonce = [...DB.flows.values()][0].nonce;
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const key = publicKey.export({ format: "jwk" });
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test-key" })).toString("base64url");
  const claims = Buffer.from(JSON.stringify({ iss: "https://accounts.google.com", aud: env.GOOGLE_CLIENT_ID, exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000), nonce, email: "qa@example.com", email_verified: true, sub: "google-sub-1" })).toString("base64url");
  const signature = sign("RSA-SHA256", Buffer.from(`${header}.${claims}`), privateKey).toString("base64url");
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async endpoint => endpoint.toString().includes("/token")
    ? Response.json({ id_token: `${header}.${claims}.${signature}` })
    : Response.json({ keys: [{ ...key, kid: "test-key", use: "sig" }] });
  try {
    const callback = await googleCallback(new Request(`https://dashboard.example/api/auth/google/callback?state=${state}&code=google-code`), env);
    assert.equal(callback.status, 302);
    const local = new URL(callback.headers.get("Location"));
    assert.equal(local.hostname, "127.0.0.1");
    assert.equal(local.searchParams.get("state"), clientState);
    const code = local.searchParams.get("code");
    const exchange = () => exchangeDesktop(new Request("https://dashboard.example/api/auth/desktop/exchange", { method: "POST", body: JSON.stringify({ code, code_verifier: verifier }) }), env);
    const issued = await exchange();
    assert.equal(issued.status, 200);
    assert.deepEqual((await issued.json()).user, { email: "qa@example.com", role: "QA" });
    assert.match(issued.headers.get("Set-Cookie"), /^sid=/);
    assert.equal((await exchange()).status, 401);
    assert.equal(DB.users.get("qa@example.com").google_sub, "google-sub-1");
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("desktop start rejects non-loopback redirect", async () => {
  const env = { DB: database(new Map()), GOOGLE_CLIENT_ID: "x", GOOGLE_CLIENT_SECRET: "y", GOOGLE_REDIRECT_URI: "https://dashboard.example/api/auth/google/callback" };
  const url = new URL("https://dashboard.example/api/auth/google/start");
  url.search = new URLSearchParams({ mode: "desktop", redirect_uri: "https://attacker.example/callback", code_challenge: "x".repeat(43), client_state: "y".repeat(43) }).toString();
  assert.equal((await startGoogle(new Request(url), env)).status, 400);
});

test("web sign-in from custom domain uses the callback domain for its state cookie", async () => {
  const env = { DB: database(new Map()), GOOGLE_CLIENT_ID: "x", GOOGLE_CLIENT_SECRET: "y", GOOGLE_REDIRECT_URI: "https://dashboard.example/api/auth/google/callback" };
  const response = await startGoogle(new Request("https://custom.example/api/auth/google/start"), env);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("Location"), "https://dashboard.example/api/auth/google/start");
  assert.equal(response.headers.get("Set-Cookie"), null);
});

test("web callback requires its browser state cookie and sets a Dashboard session", async () => {
  const DB = database(new Map([["admin@example.com", { email: "admin@example.com", role: "admin", google_sub: null }]]));
  const env = { DB, GOOGLE_CLIENT_ID: "client-id", GOOGLE_CLIENT_SECRET: "secret", GOOGLE_REDIRECT_URI: "https://dashboard.example/api/auth/google/callback" };
  const started = await startGoogle(new Request("https://dashboard.example/api/auth/google/start"), env);
  const state = new URL(started.headers.get("Location")).searchParams.get("state");
  const callbackUrl = `https://dashboard.example/api/auth/google/callback?state=${state}&code=google-code`;
  assert.equal((await googleCallback(new Request(callbackUrl), env)).status, 400);
  const restarted = await startGoogle(new Request("https://dashboard.example/api/auth/google/start"), env);
  const nextState = new URL(restarted.headers.get("Location")).searchParams.get("state");
  const nonce = [...DB.flows.values()].at(-1).nonce;
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const key = publicKey.export({ format: "jwk" });
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test-key" })).toString("base64url");
  const claims = Buffer.from(JSON.stringify({ iss: "https://accounts.google.com", aud: env.GOOGLE_CLIENT_ID, exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000), nonce, email: "admin@example.com", email_verified: true, sub: "google-admin" })).toString("base64url");
  const signature = sign("RSA-SHA256", Buffer.from(`${header}.${claims}`), privateKey).toString("base64url");
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async endpoint => endpoint.toString().includes("/token")
    ? Response.json({ id_token: `${header}.${claims}.${signature}` })
    : Response.json({ keys: [{ ...key, kid: "test-key", use: "sig" }] });
  try {
    const callback = await googleCallback(new Request(`https://dashboard.example/api/auth/google/callback?state=${nextState}&code=google-code`, { headers: { Cookie: `oauth_state=${nextState}` } }), env);
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("Location"), "/");
    assert.equal(callback.headers.getSetCookie().length, 2);
    assert.equal(DB.sessions.size, 1);
  } finally {
    globalThis.fetch = previousFetch;
  }
});
