# Google sign-in setup

The Dashboard Worker is the identity broker for the website and Mano Launcher. Google verifies the account; Dashboard's `users` table supplies its role. Only verified Google emails added by an admin may sign in. Existing users keep their Dashboard roles and bind to Google's stable account ID on first sign-in.

1. In Google Cloud, use the OAuth **Web application** client ID in `wrangler.toml`. Add this exact authorized redirect URI:

   `https://game-dashboard.mano-game.workers.dev/api/auth/google/callback`

   Make sure the OAuth consent screen permits the intended tester accounts or organization.

2. From `D:\GameDashboard`, run `npx wrangler secret put GOOGLE_CLIENT_SECRET` and enter the secret at the prompt. Do not commit or paste the secret into chat.
3. Apply D1 migration: `npx wrangler d1 migrations apply game-dashboard-db --remote`.
4. Deploy: `npx wrangler deploy`.
5. In Dashboard Settings, add each user's Google email and choose the role. `ADMIN_EMAIL` is bootstrapped as admin if no matching user exists.

The new Launcher opens the system browser for Google sign-in and receives a one-use code on a loopback callback. The Worker exchanges that code for a Dashboard session only when the local verifier matches. `LEGACY_PASSWORD_LOGIN_ENABLED=true` temporarily retains the old API for installed Launcher versions during rollout. Remove the variable from `wrangler.toml` and deploy again after users have updated; the password API then returns HTTP 410.

Run `npm test` to check the one-use desktop exchange and redirect restrictions.
