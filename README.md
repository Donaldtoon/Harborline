# Harborline Banking Simulator

An original-branded full-stack banking **simulation** for development, testing, and demonstrations. It uses Node.js, Express, PostgreSQL, bcrypt password hashing, server-side sessions, and a responsive HTML/CSS/JavaScript interface.

> **Important:** Harborline is not a bank or a financial institution. Account and routing identifiers are fictional, and deposits, withdrawals, and transfers never move real money. Do not enter real bank credentials or reuse a real password.

## Included

- Separate checking and savings accounts and balances per customer.
- Registration, login, logout, bcrypt password hashing, PostgreSQL-backed sessions, CSRF token checks, login rate limiting, and role-based admin routes.
- Simulated deposits, withdrawals, internal transfers, customer-to-customer transfers, transaction references, transaction history and filters.
- Customer profile, support tickets and threaded support messages.
- Administrator customer creation, activation/deactivation, account summary, support queue and audit log.
- PostgreSQL migration, health endpoint, Render configuration, and validation tests.

## Requirements

- Node.js 20 or newer
- PostgreSQL 14 or newer
- npm

## Run locally (Windows PowerShell or macOS/Linux)

1. Install Node.js and PostgreSQL.
2. Create an empty PostgreSQL database named `harborline_simulator`.
3. Copy `.env.example` to `.env` and edit `DATABASE_URL` for your local database. Set `SESSION_SECRET` to a random string of at least 32 characters. Never commit `.env`.
4. Install packages:
   ```sh
   npm install
   ```
5. Apply the database schema:
   ```sh
   npm run migrate
   ```
6. To create an administrator, set `ADMIN_EMAIL`, `ADMIN_PASSWORD` (12+ characters), and optionally `ADMIN_NAME` in `.env`, then run:
   ```sh
   npm run seed-admin
   ```
   The seed command creates an admin only if that email does not already exist. It does not reset or disclose existing passwords. Remove or rotate the temporary password after first use.
7. Start the server:
   ```sh
   npm start
   ```
8. Open `http://localhost:3000`. Register a customer account, or sign in with the administrator credentials. The app automatically creates separate checking and savings accounts for each new customer.
9. Run tests with `npm test`. These include amount-validation tests; they are not a substitute for end-to-end security testing against a live PostgreSQL instance.

### PowerShell notes

To create `.env`, you can run `Copy-Item .env.example .env` and then open `.env` in VS Code. Do not paste secrets into GitHub. If using environment variables directly in PowerShell, use `$env:VARIABLE_NAME = "value"` in the same terminal where you run the command.

## Deploy to Render

1. Push this project to a GitHub repository. Make sure `.env` is ignored and is not committed.
2. In Render, create a PostgreSQL database. You may use the `render.yaml` blueprint as a starting point, or create the database manually.
3. Create a Render **Web Service** from the repository using Node. Set build command to `npm install`, pre-deploy command to `npm run migrate` (if supported by your selected service plan), start command to `npm start`, and health-check path to `/api/health`.
4. Add environment variables in Render: `NODE_ENV=production`, `COOKIE_SECURE=true`, `DATABASE_URL` set to the database's **internal** connection string when services are in the same region, and `SESSION_SECRET` generated as a long random secret. Do not publish these values.
5. Run `npm run migrate` as the pre-deploy step, or run it once using a Render shell after confirming the database is attached.
6. Create the first administrator securely. Set `ADMIN_EMAIL`, `ADMIN_PASSWORD` (at least 12 characters), and `ADMIN_NAME` in the service environment, run `npm run seed-admin` once from the Render shell or a one-off job, then remove the `ADMIN_PASSWORD` variable. Keep the account's password secret. Do not use a hardcoded master password.
7. Deploy. Open the Render service URL and verify `/api/health` returns `{"status":"ok","database":"connected"}`. Then test customer registration, login/logout, separate balances, a transfer between the two accounts, transaction history, support ticket submission, and administrator-only pages.

**Render plan caveat:** availability of pre-deploy commands, persistent database plans, and blueprint options can vary by account and change over time. If your selected plan does not support a pre-deploy command, run migrations as a one-off operation before directing users to the service. Never run schema migrations concurrently from multiple web instances.

## API overview

- `GET /api/health`, `GET /api/csrf`
- `POST /api/register`, `POST /api/login`, `POST /api/logout`, `GET /api/me`, `PATCH /api/profile`
- `GET /api/transactions`
- `POST /api/deposit`, `POST /api/withdrawal`, `POST /api/transfer`
- `GET /api/support`, `POST /api/support`, `GET/POST /api/support/:id/messages`
- Admin: `GET /api/admin/overview`, `GET/POST /api/admin/customers`, `PATCH /api/admin/customers/:id/status`, `PATCH /api/admin/customers/:id/password`, `GET /api/admin/customers/:id/accounts`, `POST /api/admin/customers/:id/adjustments`, `GET /api/admin/tickets`, `PATCH /api/admin/tickets/:id`

Mutating requests (except login/logout) require the session CSRF token in `x-csrf-token`; the frontend handles this automatically. Money amounts are validated on the server and stored in PostgreSQL `NUMERIC(14,2)` columns. Financial operations use database transactions and optional idempotency keys.

## Production checklist / known scope

- Use a managed PostgreSQL database with backups, TLS, access controls, and monitoring.
- Configure a strong unique session secret, HTTPS, a supported Node runtime, and appropriate rate limits.
- Perform independent security review and end-to-end tests before any public use.
- This starter implementation does not connect to payment networks, verify identity, provide real statements, or support real money. Account identifiers are marked as simulated. The displayed routing value is a fictional simulator label, not a valid US routing number.
- Customer self-service email password reset, downloadable statements, granular permission management, and comprehensive audit coverage are not included in this initial version. Administrators can reset a customer's password to a new temporary password and adjust simulated balances; these actions are audited. Share temporary passwords only through a secure channel and require a separate password-change workflow before broader production-style use.
