# WVCXXosint.XD — OSINT Spider

OSINT Spider is a local-first, Russian/English interface for first-pass research of publicly available information. It runs independent checks, streams their actual outcomes into a React Flow graph, and labels relationships as checks rather than implying that every result is an identity link.

## Current stack

- Frontend: React 19, Vite, React Flow, Dagre.
- Backend: FastAPI, WebSocket, Python async DNS/HTTP clients.
- History: browser `localStorage` (up to 50 investigations); server-side monitoring history is stored in a local SQLite file (`backend/monitoring.db`, gitignored).
- Integrations and actual configuration state are returned by `GET /api/tools`.

## Run locally

Requirements: Python 3.10+ and Node.js 20.19+ or 22.12+.

1. Configure optional backend credentials from **Settings → Source configuration** after starting the app. The backend stores application-managed keys in ignored `backend/settings.json` with owner-only permissions (`0600` on POSIX); values are never returned to the frontend. Keys in this file are not encrypted at rest. Existing `backend/.env` values remain supported as a fallback.

   Settings supports GitHub, HIBP, Shodan, VirusTotal, AbuseIPDB, Censys API ID/secret, urlscan.io, and Search API credentials. GitHub, HIBP, and Shodan adapters are implemented; saving credentials for the other providers does not enable checks until their adapters exist. For environment-managed deployments, copy `backend/.env.example` to `backend/.env`; an application-saved credential takes precedence over its environment value.

2. Start the backend in one terminal:

   ```powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```

3. Start the frontend in a second terminal:

   ```powershell
   cd frontend
   npm ci
   npm run dev
   ```

   Open the URL printed by Vite (normally `http://localhost:5173`).

## Working features

- Query types: auto-detection, email, username, domain, public IP, URL, phone, and organization.
- Live graph with pan/zoom, drag, node details, status filters, graph search, branch hiding, fit-to-view, category grouping with collapsible groups, loading placeholders that are replaced by real results, timeline view, and mobile result feed.
- Executed public checks: DNS mail records and public-host validation, bounded website metadata (no automatic redirects), domain NS/SPF/DMARC records, domain WHOIS, Internet Archive snapshot lookup, optional local theHarvester, public GitHub profile/commit metadata, Gravatar, OpenPGP public-key lookup, optional HIBP and Shodan, phone numbering-plan metadata, IP RDAP, crt.sh certificate names for depth 2–3, email infrastructure checks (SMTP/MX), public organization registries (Wikidata + GitHub organizations), local ExifTool metadata extraction for uploaded files, and WhatsMyName public username dataset probes with confirmed/possible/absent/inconclusive verdicts.
- Investigation workflow: per-node confidence, source links and timestamps, cancellation with partial-result saving, selective retry for failed/rate-limited checks, deep dives, local notes, history labels and tags, diffs, and JSON/CSV/SVG/Markdown/PDF exports with evidence metadata.
- Scheduled monitoring: create a watch (query + type + depth + interval), the backend re-runs checks on a schedule, stores the last diff (added/changed/removed checks), and exposes `GET/POST/DELETE /api/watch`.
- ExifTool tool card with drag-and-drop file upload processed by the local binary on the backend (25 MB limit, interesting metadata groups only).
- GUI: three-column layout, command palette, backend health status and in-app API-key settings, copy-to-clipboard, relative timestamps, light/dark theme, and RU/EN language switch.
- Investigation history stays in the browser and can be reopened, compared, or deleted.

## Safety and limitations

- Only public IP targets are accepted. URL inputs must be HTTP(S), use a public hostname, contain no user credentials, and use a standard port. DNS answers are checked before website requests, pinned to a validated public address, and redirects are not followed.
- IP RDAP redirects are followed manually only after validating and resolving each HTTPS destination as public.
- Username existence is confirmed only through exact public-source verdicts (GitHub API response, WhatsMyName dataset body-code markers); single HTTP responses never confirm an identity on their own.
- No result means only that the selected source returned no match. It is not evidence that an account, breach, or relationship does not exist. WhatsMyName marks a profile confirmed only on an exact expected body-code match, possible when the code matches without the marker, and inconclusive otherwise.
- HIBP results contain breach names only, never leaked passwords or breach contents.
- API-key management endpoints accept only loopback clients and the configured local frontend origins. `backend/settings.json` is plaintext on disk; protect the OS account and filesystem backups accordingly.
- Search templates, demo data, password-reset checks, private account access, and vulnerability exploitation are not part of the application.
- Depth applies to domain/URL/email investigations and controls the certificate-transparency subdomain depth. Other query types run at depth 1.
- ExifTool runs only on locally uploaded files and never phones home; the binary must be installed on the server. No demo data, no login-reset checks, no private sources.

## Tests and checks

Backend tests:

```powershell
cd backend
python -m unittest discover -s tests
```

Frontend:

```powershell
cd frontend
npm run lint
npm run build
```
