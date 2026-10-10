# PhishShield

PhishShield is a phishing email analysis application with a web dashboard and a Gmail Workspace add-on. It analyzes email headers and content, scores potential risk indicators, stores investigations in PostgreSQL, and can optionally enrich domain lookups with VirusTotal and URLScan.

> **Important:** Risk scores are indicators to help with investigation, not a guarantee that an email is safe or malicious. Verify suspicious requests through a trusted channel.

## Features

- Analyze `.eml` files and email text from the web dashboard.
- Review sender and reply-to details, authentication headers, URLs, attachments, and risk-scoring factors.
- Save and review investigations in PostgreSQL.
- Connect the Gmail add-on to a PhishShield account and analyze the currently opened message.
- Manage analyst accounts from the admin dashboard.
- Optionally look up domains using VirusTotal and URLScan API keys.
- Download investigation reports from the dashboard.

## Architecture

- **Web app and API:** Node.js 20+, Express, and the React-based `index.html` frontend.
- **Database:** PostgreSQL. The application initializes the schema in `db/schema.sql` at startup when `DATABASE_URL` is configured.
- **Gmail add-on:** Google Apps Script source and manifest in [`gmail-addon/`](./gmail-addon/).
- **Deployment:** Render blueprint in [`render.yaml`](./render.yaml); it provisions a Node web service and PostgreSQL database.

The Render blueprint is configured to deploy the `fullstack` branch. The `main` branch may not contain the same full-stack application files.

## Requirements

- Node.js 20 or newer and npm.
- PostgreSQL for login, saved investigations, and other database-backed features.
- A Google account and Gmail for installing/testing the Apps Script add-on.

## Run locally

1. Clone the repository and switch to the full-stack branch:

   ```bash
   git clone --branch fullstack https://github.com/utkarsh-r32/PhishShield.git
   cd PhishShield
   ```

2. Install dependencies and create your local environment file:

   ```bash
   npm ci
   cp .env.example .env
   ```

   On Windows PowerShell, use `Copy-Item .env.example .env` instead of `cp` if needed.

3. Edit `.env` and set at least:

   ```dotenv
   PORT=10000
   NODE_ENV=development
   DATABASE_URL=postgresql://<user>:<password>@localhost:5432/phishshield
   JWT_SECRET=<a-long-random-secret>
   ADMIN_EMAIL=admin@example.com
   ADMIN_PASSWORD=<a-strong-password>
   COOKIE_SECURE=false
   ```

   `ADMIN_EMAIL` and `ADMIN_PASSWORD` are used to create the initial administrator on startup if that email does not already exist. Use a unique, strong password. Keep `.env` private; it is ignored by Git. `VIRUSTOTAL_API_KEY` and `URLSCAN_API_KEY` are optional and can be left blank.

4. Start the app:

   ```bash
   npm run dev
   ```

   Open `http://localhost:10000`. For a non-watch process, use `npm start`. The API health endpoint is `http://localhost:10000/health`.

If `DATABASE_URL` is omitted, the server can start in limited mode, but database-backed login and investigation features will not be available.

## Deploy to Render

The repository includes a Render Blueprint (`render.yaml`) configured for the `fullstack` branch.

1. In Render, create a new Blueprint deployment and select this repository and the `fullstack` branch.
2. Review the web service and PostgreSQL database resources described by the blueprint.
3. Set the prompted `ADMIN_EMAIL` and `ADMIN_PASSWORD` values in Render. The blueprint generates `JWT_SECRET`, sets production cookie/security options, and connects the database.
4. Optionally configure `VIRUSTOTAL_API_KEY` and `URLSCAN_API_KEY` as Render environment variables.
5. After deployment, check `/health`. A healthy response should report `"status":"HEALTHY"` and `"database":"connected"`.

The web service serves the frontend and API from the same origin. Do not put API keys or database credentials in frontend code.

## Gmail add-on setup

The add-on source is in [`gmail-addon/Code.gs`](./gmail-addon/Code.gs), and its Apps Script manifest is [`gmail-addon/appsscript.json`](./gmail-addon/appsscript.json). The configured API base URL currently points to `https://phishshield-app.onrender.com`; update `PHISHSHIELD_API` in `Code.gs` if you use a different backend URL.

1. Deploy PhishShield and create/sign in to an administrator or analyst account.
2. In PhishShield, use the Gmail integration controls to create a connection token. Treat the token like a password; it grants access to analyze emails for that account.
3. Create an Apps Script project. Add the contents of `Code.gs`, and enable **Show `appsscript.json` manifest file** in Project Settings to copy the repository manifest.
4. Save the project. In Apps Script, create a test deployment for the Google Workspace add-on and install it for your Google account.
5. Open Gmail, open a message, launch PhishShield, and enter the connection token when prompted. Analyze the message and review the returned risk level, score, and findings.

The add-on sends the currently opened message to the configured PhishShield backend. Gmail message content is therefore processed by that service and stored as an investigation under the connected account. Revoke the Gmail connection in PhishShield or disconnect the add-on when access is no longer needed. Google may require OAuth consent configuration and verification before distributing the add-on beyond test users.

## API overview

Authenticated web endpoints use the PhishShield session cookie. Gmail analysis uses a bearer connection token generated by the authenticated account.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Service and database health |
| `POST` | `/api/auth/login` | Sign in and create a session |
| `POST` | `/api/auth/logout` | End the current session |
| `GET` | `/api/auth/me` | Get the current account |
| `GET` | `/api/investigations` | List the current account's investigations |
| `POST` | `/api/v1/analyze-eml` | Analyze an uploaded `.eml` file |
| `POST` | `/api/v1/analyze-text` | Analyze submitted email text |
| `POST` | `/api/integrations/gmail/connect` | Create a Gmail connection token |
| `POST` | `/api/integrations/gmail/revoke` | Revoke Gmail connections for the current account |
| `POST` | `/api/v1/analyze-gmail` | Analyze a Gmail message using a bearer connection token |
| `GET` | `/api/intel/domain` | Query configured domain threat-intelligence sources |
| `GET` / `POST` | `/api/admin/users` | List or create users (administrator only) |

All API routes are rate-limited. See [`server.js`](./server.js) for request formats and implementation details.

## Project files

- `server.js` — Express API, authentication, analysis, Gmail integration, and database setup.
- `index.html` — Web dashboard and frontend.
- `db/schema.sql` — PostgreSQL schema.
- `gmail-addon/Code.gs` — Google Apps Script Gmail add-on.
- `gmail-addon/appsscript.json` — Apps Script add-on manifest.
- `render.yaml` — Render web service and PostgreSQL blueprint.
- `.env.example` — Local environment variable template.

## Validation

The GitHub Actions workflow checks the server JavaScript syntax on pushes to `main` and `fullstack` and pull requests targeting `main`.

```bash
node --check server.js
```
