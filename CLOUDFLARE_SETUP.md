# Cloudflare Deployment

This project now has a Cloudflare-native dashboard in `src/worker.js`.

It uses:

- Cloudflare Workers for the dashboard/backend
- Cloudflare D1 for users, sessions, projects, and build metadata
- Cloudflare R2 for build artifacts
- Direct browser-to-R2 uploads through presigned PUT URLs

## 1. Create Cloudflare resources

```bash
npx wrangler d1 create game-dashboard-db
npx wrangler r2 bucket create game-dashboard-builds
```

Copy the returned D1 `database_id` into `wrangler.toml`.

## 2. Create R2 API token

Cloudflare Dashboard -> R2 -> Manage R2 API Tokens -> Create API token.

Use permissions that can read/write objects for the `game-dashboard-builds` bucket.

## 3. Configure Worker secrets

```bash
npx wrangler secret put ADMIN_EMAIL
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put DASHBOARD_API_TOKEN
npx wrangler secret put R2_ACCESS_KEY_ID
npx wrangler secret put R2_SECRET_ACCESS_KEY
```

Set `R2_ACCOUNT_ID`, `R2_BUCKET_NAME`, and optional `R2_PUBLIC_URL` in `wrangler.toml`.

## 4. Apply D1 schema

```bash
npx wrangler d1 migrations apply game-dashboard-db --remote
```

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
npm run dev
npm run deploy
```
