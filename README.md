# CyberGuard AI

A full-stack cybersecurity education app. Users check passwords, scan links and analyse
suspicious messages; a rules engine scores the risk, and Google Gemini explains the result
in plain language. An AI tutor answers security questions in English, Urdu or Roman Urdu.

**Stack:** Django 6 · Django REST Framework · SimpleJWT · PostgreSQL · Vue 3 · Vite · Pinia · Google Gemini

## Features

| Tool | What it does |
|---|---|
| **Password check** | Live strength score, entropy estimate and crack time under four attack models. Detects leaked passwords (20k list), dictionary words, l33t swaps, keyboard walks, sequences, years and `Word2004!` shapes. The password is never stored or sent to the AI. |
| **Link scanner** | Offline URL analysis — the link is never opened. Flags typosquats (`paypa1.com`), brand-in-subdomain tricks, `@` redirects, raw/obfuscated IPs, punycode, shorteners, high-abuse TLDs, risky downloads and embedded redirects. Accepts defanged links (`hxxp://site[.]com`). |
| **Message check** | Phishing detection for email/SMS/WhatsApp: urgency, threats, OTP/password requests, money and gift-card asks, prizes, sender/display-name and Reply-To mismatches, free-mail "organisations", hidden link destinations, risky attachments. Understands common Roman Urdu scam phrasing. Every link is run through the link scanner. |
| **AI explanations** | One click turns a report into a short lesson. Explanations are cached per scan. |
| **AI tutor** | Gemini chat with conversation memory, scoped to defensive security. |
| **History & overview** | Saved reports, filters, risk distribution and averages. |

### Design decision: rules decide, AI explains

Every score and verdict comes from deterministic heuristics in
`backend/security/analyzers/`. Gemini only receives a *sanitised* copy of the result and
is instructed never to change the verdict. This keeps results consistent, testable and
free of hallucinated risk levels — and the app keeps working with no API key (explanations
fall back to templates generated from the findings).

## Project structure

```
cyberguard-ai/
├── backend/                 Django REST API
│   ├── config/              settings (env-driven), urls
│   ├── accounts/            register, JWT login/refresh/logout, me
│   ├── security/
│   │   ├── analyzers/       password.py · url.py · phishing.py (pure Python)
│   │   ├── ai.py            Gemini client, prompts, sanitising, fallbacks
│   │   ├── models.py        ScanRecord, ChatMessage
│   │   ├── views.py         analyze, scans (history/explain), stats, chat
│   │   └── tests.py         31 tests
│   ├── build.sh             Render build script
│   └── Dockerfile
├── frontend/                Vue 3 + Vite SPA
│   ├── src/views/           one page per tool
│   ├── src/components/      RiskRuler, ScanReport, AiExplain, …
│   ├── vercel.json
│   └── Dockerfile, nginx.conf
├── render.yaml              Render blueprint (backend)
└── docker-compose.yml       whole stack on one machine
```

## Run locally

Requirements: Python 3.12+ and Node 20+.

```bash
# 1) Backend
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # set DEBUG=True and (optionally) GEMINI_API_KEY
python manage.py migrate
python manage.py createsuperuser   # optional, for /admin
python manage.py runserver

# 2) Frontend (new terminal)
cd frontend
npm install
npm run dev                        # http://localhost:5173
```

Vite proxies `/api` to `http://127.0.0.1:8000`, so no CORS setup is needed locally.

Run the tests: `cd backend && python manage.py test`

## Deploy for free (Neon + Render + Vercel)

| Part | Host | Free tier notes |
|---|---|---|
| Database | [Neon](https://neon.com) | Postgres, no expiry, no card needed. Sleeps after 5 min idle, wakes automatically. |
| Backend | [Render](https://render.com) | Free web service sleeps after 15 min idle; first request after that takes ~1 min. |
| Frontend | [Vercel](https://vercel.com) | Static hosting with global CDN. |
| AI | [Google AI Studio](https://aistudio.google.com/apikey) | Free Gemini API key (rate-limited). |

Render's own free Postgres is deleted after 30 days, which is why the database is on Neon.

**0. Push to GitHub.** Create a repo and push this folder (`.env` files are ignored).

**1. Database — Neon.** Create a project → copy the connection string
(`postgresql://…neon.tech/neondb?sslmode=require`).

**2. Gemini key.** Create one at aistudio.google.com/apikey. (Optional — the app works without it.)

**3. Backend — Render.** Dashboard → **New → Blueprint** → select the repo. Render reads
`render.yaml` and asks for:
- `DATABASE_URL` — the Neon string
- `CORS_ALLOWED_ORIGINS` — put `https://placeholder.vercel.app` for now; you'll fix it in step 5
- `GEMINI_API_KEY` — your key

Wait for the deploy, then open `https://<your-service>.onrender.com/api/health/` — you
should see `{"status": "ok"}`.

To get an admin account, add `DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_EMAIL` and
`DJANGO_SUPERUSER_PASSWORD` in the service's Environment tab and redeploy once (free
instances have no shell). Admin is at `/admin/`.

**4. Frontend — Vercel.** **Add New → Project** → import the repo → set **Root Directory**
to `frontend` → add environment variable `VITE_API_URL` = `https://<your-service>.onrender.com`
→ Deploy.

**5. Connect them.** In Render → Environment, set `CORS_ALLOWED_ORIGINS` to your Vercel URL
(e.g. `https://cyberguard-ai.vercel.app`, no trailing slash). Save — Render redeploys.
To also allow Vercel preview URLs, set `CORS_ALLOWED_ORIGIN_REGEX` to
`^https://cyberguard-ai.*\.vercel\.app$`.

Open the Vercel URL, create an account, and you're live.

## Deploy with Docker (any VPS or your laptop)

```bash
cp .env.example .env      # set SECRET_KEY, POSTGRES_PASSWORD, GEMINI_API_KEY
docker compose up --build
```

Open http://localhost:8080. nginx serves the app and proxies `/api` and `/admin` to
Django; Postgres data lives in a named volume. On a public server, put HTTPS in front
(Caddy, Cloudflare Tunnel or certbot) and set `SECURE_SSL_REDIRECT=True`,
`ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` for your domain.

## Environment variables (backend)

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | — (required when `DEBUG=False`) | Django signing key |
| `DEBUG` | `False` | Never `True` in production |
| `DATABASE_URL` | SQLite file | Postgres URL in production |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Render's hostname is added automatically |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173` | Frontend origin(s), comma-separated |
| `CORS_ALLOWED_ORIGIN_REGEX` | — | Optional regex for preview deployments |
| `GEMINI_API_KEY` | — | Enables AI explanations and chat |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Any Gemini text model |
| `JWT_ACCESS_MINUTES` / `JWT_REFRESH_DAYS` | `30` / `7` | Token lifetimes |
| `THROTTLE_AI` / `THROTTLE_AUTH` | `20/min` / `10/min` | Rate limits |
| `SECURE_SSL_REDIRECT` | `True` | Set `False` only behind plain HTTP (Docker locally) |

Frontend: `VITE_API_URL` — backend origin, empty for local dev.

## API

All endpoints except register/login/refresh/health need `Authorization: Bearer <access>`.

| Method | Path | Body / notes |
|---|---|---|
| POST | `/api/auth/register/` | `username, email, password` → user + tokens |
| POST | `/api/auth/login/` | `username, password` → `access, refresh` |
| POST | `/api/auth/refresh/` | `refresh` → new pair (old refresh is blacklisted) |
| POST | `/api/auth/logout/` | `refresh` → blacklists it |
| GET | `/api/auth/me/` | current user |
| POST | `/api/analyze/password/` | `password, save?` |
| POST | `/api/analyze/url/` | `url, save?` |
| POST | `/api/analyze/phishing/` | `body, subject?, sender?, reply_to?, save?` |
| GET | `/api/scans/?kind=&page=` | history (paginated) |
| GET / DELETE | `/api/scans/{id}/` | full report / delete |
| POST | `/api/scans/{id}/explain/` | AI explanation (cached) |
| DELETE | `/api/scans/clear/` | delete all of your scans |
| GET | `/api/stats/` | overview numbers |
| GET / POST / DELETE | `/api/chat/` | history / `message` / clear |
| GET | `/api/health/` | public health check |

## Security notes

- Passwords submitted for analysis are never persisted or logged; history stores only a masked length label, and the AI never receives them.
- Links are analysed statically — the server never fetches user-supplied URLs (no SSRF surface).
- AI output is rendered through `marked` + `DOMPurify`.
- JWT refresh rotation with blacklisting; scoped rate limits on auth and AI endpoints.
- Users can only read their own scans and chats (tested).
- Production settings: HTTPS redirect, secure cookies, HSTS, `nosniff`, `X-Frame-Options: DENY`.

## Troubleshooting

- **"Can't reach the server" on first load** — the free Render instance is waking up. Wait ~1 minute and retry.
- **CORS error in the browser console** — `CORS_ALLOWED_ORIGINS` on Render must exactly match the Vercel URL (scheme included, no trailing slash).
- **Explanations say "AI explanations are unavailable"** — check `GEMINI_API_KEY` on Render; the Gemini free tier is rate-limited, so wait a minute and use "Try the AI again".
- **Refreshing a page on Vercel gives 404** — make sure the Vercel Root Directory is `frontend` so `vercel.json` is used.
