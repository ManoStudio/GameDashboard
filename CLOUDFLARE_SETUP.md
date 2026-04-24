# Cloudflare Deployment

This project now has a Cloudflare-native dashboard in `src/worker.js`.

It uses:

- Cloudflare Workers for the dashboard/backend
- Cloudflare D1 for users, sessions, projects, and build metadata
- Cloudflare R2 for build artifacts
- Direct browser-to-R2 uploads through presigned PUT URLs

## 1. Create Cloudflare resources

```bash
npm run db:create
npm run r2:create
```

Copy the returned D1 `database_id` into `wrangler.toml`.

Example output:

```toml
[[d1_databases]]
binding = "DB"
database_name = "game-dashboard-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

The deploy will fail with this error until the placeholder is replaced:

```text
binding DB of type d1 must have a valid `database_id` specified
```

## 2. Create R2 API token

Cloudflare Dashboard -> R2 -> Manage R2 API Tokens -> Create API token.

Use permissions that can read/write objects for the `game-dashboard-builds` bucket.

## 3. Configure Worker secrets

Run these commands from the repository root, the same folder that contains `wrangler.toml`.

```bash
npx wrangler secret put ADMIN_EMAIL
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put DASHBOARD_API_TOKEN
npx wrangler secret put R2_ACCESS_KEY_ID
npx wrangler secret put R2_SECRET_ACCESS_KEY
```

If Wrangler says the Worker name is missing, it is not reading `wrangler.toml`. Use:

```bash
npx wrangler secret put ADMIN_EMAIL --config wrangler.toml
npx wrangler secret put ADMIN_PASSWORD --config wrangler.toml
npx wrangler secret put DASHBOARD_API_TOKEN --config wrangler.toml
npx wrangler secret put R2_ACCESS_KEY_ID --config wrangler.toml
npx wrangler secret put R2_SECRET_ACCESS_KEY --config wrangler.toml
```

Set `R2_ACCOUNT_ID`, `R2_BUCKET_NAME`, and optional `R2_PUBLIC_URL` in `wrangler.toml`.

Your deploy log already shows the account id in the failed API path:

```text
/accounts/4956abaf4d499cde396a8c7ebf6061c6/...
```

So `R2_ACCOUNT_ID` should be:

```toml
R2_ACCOUNT_ID = "4956abaf4d499cde396a8c7ebf6061c6"
```

## 4. Apply D1 schema

```bash
npx wrangler d1 migrations apply game-dashboard-db --remote
```

The Worker also runs `CREATE TABLE IF NOT EXISTS` on startup as a safety net, but applying migrations is still recommended so the database is ready before traffic arrives.

For local development:

```bash
npx wrangler d1 migrations apply game-dashboard-db --local
```

## 5. Configure R2 CORS

In Cloudflare Dashboard -> R2 -> bucket -> Settings -> CORS policy, use `r2-cors.json`.

Replace the placeholder origin with your real Worker domain.

## 6. Run or deploy

```bash
npm install
npm run db:migrate
npm run dev
npm run deploy
```

## Cloudflare Pages build settings

Use this deploy command:

```bash
npx wrangler deploy
```

This project no longer needs Python dependencies for Cloudflare. If Pages still runs `pip install -r requirements.txt`, remove the old Python deployment files from the Cloudflare-connected branch or set the project as a Workers deployment that uses `wrangler.toml`.
