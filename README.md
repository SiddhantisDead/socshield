# SOCShield — SOC Analyst Simulation Platform

A web-based Security Operations Center (SOC) simulator: ingest security logs, detect
threats with real [Sigma](https://github.com/SigmaHQ/sigma) rule logic and
[YARA](https://virustotal.github.io/yara/), map findings to MITRE ATT&CK, and
investigate the resulting alerts through a dark-themed analyst console.

![stack](https://img.shields.io/badge/backend-FastAPI-009688) ![stack](https://img.shields.io/badge/frontend-React%20%2B%20TypeScript-3178C6) ![stack](https://img.shields.io/badge/detection-pySigma%20%2B%20YARA-blue)

## Quickstart

### Option A — Docker Compose

```bash
docker-compose up --build
```

- Frontend: http://localhost:8080
- Backend API + docs: http://localhost:8000/docs

The backend container seeds demo users and ingests the bundled sample datasets on
first boot automatically.

### Option B — Local dev

**Backend**

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m app.seed --with-data      # creates demo users + ingests datasets/ + runs detection
uvicorn app.main:app --reload       # http://localhost:8000
```

**Frontend** (separate terminal)

```bash
cd frontend
npm install
npm run dev                         # http://localhost:5173, proxies /api to :8000
```

### Demo accounts

| Username  | Password    | Role    |
|-----------|-------------|---------|
| `admin`   | `admin123`  | admin   |
| `analyst` | `analyst123`| analyst |

## What's actually implemented

This was built depth-first: the core platform is fully functional end-to-end, not
just scaffolding.

- **Auth** — JWT (PyJWT + bcrypt), role-based (`admin`/`analyst`) dependencies on every route.
- **Log ingestion** — custom parsers for Windows Event Logs (JSON export), Linux
  `auth.log`, Apache/Nginx combined access logs, firewall logs, and DNS query logs.
  Search, filter (severity/hostname/IP/type/time), and CSV/JSON export.
- **Detection engine** — a genuine [pySigma](https://github.com/SigmaHQ/pySigma)
  integration: `backend/app/detection/backend.py` implements a custom pySigma
  `Backend` subclass that compiles parsed Sigma rules directly into Python
  predicate closures (`dict -> bool`) instead of a SIEM query string. This means
  full Sigma condition logic — AND/OR/NOT, wildcards, regex, CIDR, numeric
  comparisons, field-exists — runs natively in-process against ingested logs.
  10 bundled rules in `sigma_rules/` cover brute-force probing, credential
  dumping, persistence, malicious macros, encoded PowerShell, SQLi, sensitive
  file access, and C2-like DNS.
- **Brute-force correlation** — the one detection pattern real Sigma can't do
  without a stateful correlation backend ("5 failed logins in 10 minutes ->
  alert") is handled by a small hand-rolled sliding-window pass
  (`backend/app/detection/correlation.py`), run alongside per-event Sigma
  matching.
- **YARA scanning** — real `yara-python`, loading rules from `yara_rules/`.
  Try it against the safe sample files in `datasets/malware/` (webshell pattern,
  mimikatz string reference, PowerShell downloader pattern, and the industry-
  standard EICAR test string — none of these are actual malware).
- **MITRE ATT&CK mapping** — Sigma rule tags (`attack.txxxx`) and YARA rule
  metadata are mapped to technique IDs/names via `detection/mitre_mapper.py`.
- **Incident management** — alerts promote to incidents with status
  (Open/Investigating/Resolved/Closed), assignment, resolution notes, and a
  running timeline of analyst notes + next actions.
- **Threat intel** — `GET /api/threat-intel?ip=` calls AbuseIPDB/VirusTotal when
  an API key is configured in `backend/.env`, and otherwise returns a
  deterministic mock response (same response shape either way) so the feature
  is fully demoable without paid API access.
- **Dashboard** — total logs/alerts, severity breakdown, hourly attack timeline,
  daily alert trend, top source IPs, and a MITRE ATT&CK heatmap, all computed
  live from the database.

## Design tradeoffs (read before assuming SigmaHQ rule compatibility)

- Sigma rules here use a **custom normalized field schema** (`EventID`,
  `SourceIp`, `Process`, `Action`, …) chosen to match this project's own log
  parsers — not the raw Windows XML event schema SigmaHQ's public rule
  repository targets. Community Sigma rules from `github.com/SigmaHQ/sigma`
  will **not** match out of the box; you'd need a field-mapping pipeline
  (pySigma supports this) to translate them. Writing rules against your own
  normalized schema after log parsing is a common real-world pattern (e.g.
  after CIM normalization in Splunk).
- "Windows Event Log" ingestion parses **JSON-exported** events (e.g.
  `wevtutil qe /f:json`), not raw binary `.evtx` — same fields analysts pivot
  on, without the binary-format parsing complexity.
- Sigma **correlation rules** (the official spec for "N events in M minutes")
  are explicitly unsupported by the custom backend — see `correlation.py`
  above for how that gap is covered instead.
- GeoIP lookups (`backend/app/utils/geoip.py`) use a small static table, not a
  real MaxMind database (that requires a registered license key). Swap in
  `geoip2.database.Reader` once you have one.

## API

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | Create a user |
| POST | `/api/auth/login` | JWT login |
| GET | `/api/auth/me` | Current user |
| POST | `/api/upload-log` | Upload + parse + detect on a log file |
| GET | `/api/logs` | List/search/filter logs |
| GET | `/api/logs/export` | CSV/JSON export |
| GET | `/api/alerts` | List/filter alerts |
| PUT | `/api/alerts/{id}/status` | Update alert status |
| POST | `/api/alerts/rescan` | Reload Sigma rules + re-run detection over all logs |
| POST | `/api/incident` | Create incident from an alert |
| GET | `/api/incidents` | List incidents |
| PUT | `/api/incident/{id}` | Update status/assignment/resolution |
| POST | `/api/incidents/{id}/notes` | Add analyst note |
| GET | `/api/dashboard` | Aggregated dashboard stats |
| POST | `/api/scan` | YARA-scan an uploaded file |
| GET | `/api/threat-intel?ip=` | IP reputation (real or mock) |

Full interactive docs at `/docs` (Swagger) once the backend is running.

## Project layout

```
backend/app/
  api/          FastAPI routers (one per resource)
  auth/         JWT + password hashing + role dependencies
  detection/    Sigma backend, Sigma engine, correlation, YARA engine, MITRE mapper
  models/       SQLAlchemy models
  parsers/      windows / linux / apache / firewall / dns log parsers
  schemas/      Pydantic request/response models
  seed.py       Demo user + sample dataset bootstrap script
frontend/src/
  pages/        Dashboard, Alerts, Incident, Login, ThreatIntel, LogViewerPage, Scan
  components/   Sidebar, Navbar, Layout, Charts, LogViewer, SeverityBadge, StatCard
  services/     axios API client
  context/      AuthContext (JWT persisted to localStorage)
sigma_rules/    10 Sigma detection rules
yara_rules/     4 YARA rules
datasets/       Synthetic sample logs + generate_datasets.py + safe malware-pattern samples
docker/         Dockerfiles + nginx.conf
```

## Regenerating the sample datasets

```bash
cd datasets && python3 generate_datasets.py
```

Produces a mix of benign background traffic and embedded attack scenarios
(RDP/SSH brute force bursts, credential dumping via `sudo cat /etc/shadow`, a
UID-0 backdoor account, encoded PowerShell, a malicious Office macro, SQLi and
sensitive-file web probes, port scanning, and DGA-like DNS) so every bundled
Sigma rule and the brute-force correlation both fire on first ingestion.

## Not yet wired up

- Real-time updates via WebSockets (Phase 3 stretch goal from the original spec).

## Deploying to Vercel (frontend) + Render (backend) + Neon (database)

Render is used instead of Heroku here because its free web service tier
doesn't require a credit/debit card — Heroku, Railway, and Fly.io all added
mandatory card verification even for student/free tiers. Vercel is free and
handles the monorepo natively, and Neon gives a free managed Postgres (Render's
free tier filesystem is also ephemeral/reset on redeploy, so a managed
Postgres is not optional once you leave Docker/local dev).

### 1. Database — Neon

1. Create a free project at [neon.tech](https://neon.tech).
2. Copy the connection string it gives you (starts with `postgresql://`).

### 2. Backend — Render

Render can build directly from `docker/backend.Dockerfile`, so nothing extra
needs to be added to the repo for this path — it reuses the exact same image
that's already tested working via `docker-compose`.

1. New "Web Service" on [render.com](https://render.com) → connect the GitHub repo.
2. Runtime: **Docker**. Dockerfile path: `docker/backend.Dockerfile`. Docker build context: `.` (repo root).
3. Environment variables (Render dashboard → Environment):
   - `DATABASE_URL` = your Neon connection string
   - `JWT_SECRET` = a random value (generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`)
   - `CORS_ORIGINS` = `https://siddhantdev.me,https://www.siddhantdev.me`
4. Deploy. The container's `CMD` already runs `app.seed --with-data` before
   starting uvicorn on every boot — it's idempotent (skips if users/logs
   already exist), so that's safe to leave as-is.
5. Render gives you a `your-app.onrender.com` URL immediately. To use
   `api.siddhantdev.me` instead: Render dashboard → Settings → Custom Domain →
   add `api.siddhantdev.me`, then add the CNAME record it gives you in your
   domain's DNS settings.

Note: Render's free tier spins the service down after ~15 minutes of
inactivity and takes ~30-60s to wake back up on the next request — expected
behavior on free tier, not a bug, but worth knowing before a demo.

### 3. Frontend — Vercel

1. Import the GitHub repo into Vercel.
2. Set **Root Directory** to `frontend` in the project settings.
3. Add an environment variable: `VITE_API_BASE_URL` = `https://api.siddhantdev.me/api`
   (or Render's default `.onrender.com` URL + `/api` if you haven't added the
   custom subdomain yet).
4. Deploy. `frontend/vercel.json` already handles the SPA routing rewrite
   (without it, refreshing on a route like `/alerts` would 404).
5. In Vercel's domain settings, add `siddhantdev.me` (and `www.siddhantdev.me`
   if desired) and follow its DNS instructions for your registrar.

### Result

- `https://siddhantdev.me` → React frontend (Vercel)
- `https://api.siddhantdev.me` → FastAPI backend (Render)
- Postgres (Neon) persists data across Render restarts/deploys

### If you get Heroku access later

The repo root also has a `Procfile`, root-level `requirements.txt` (points at
`backend/requirements.txt`), `.python-version`, and `.slugignore` left in place
for that path — `heroku create` + `heroku config:set` (same env vars as above)
+ `git push heroku main` would work unchanged if a card ever stops being a
blocker.
