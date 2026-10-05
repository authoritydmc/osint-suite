# 🛰️ RajLabs OSINT & NUMINT Intelligence Suite

A unified, modern Open-Source Intelligence (OSINT) and Telecom Number Intelligence (NUMINT) investigation suite with glassmorphic dark-mode dashboard, high-concurrency async recon engines, and Authentik SSO support.

---

## ⚡ Features
- 📱 **Phone NUMINT:** E.164 standardization, international telecom operator detection, Indian regional circles, carrier discovery, timezone mapping, and fraud risk indicators.
- 🔍 **Sherlock Identity Recon:** High-concurrency async username scans across 20+ top developer & social platforms (GitHub, Reddit, Telegram, DockerHub, Dev.to, NPM, PyPI, Keybase, etc.).
- 🌐 **DNS & Domain Intelligence:** Comprehensive A, AAAA, MX, TXT, NS record resolution, Cloudflare edge detection, and fast top-level subdomain discovery.
- 🛰️ **IP & ASN Geolocation:** Autonomous System Number (ASN), ISP organization, country/city coordinates, and timezone lookups.
- 🎨 **Modern Dark UI:** Glassmorphic Vue 3 & Tailwind CSS single-page interface with direct deep links to Google Dorks, Truecaller, WhatsApp, and Telegram.

---

## 🚀 Quickstart (Docker)

```bash
docker build -t rajlabs/osint-suite:latest .
docker run -d -p 8000:8000 --name osint-suite rajlabs/osint-suite:latest
```

Navigate to `http://localhost:8000` or `https://osint.rajlabs.in`.

## 🔑 API keys (all optional)

Every lookup works keyless; keys unlock live validation (Numverify, Abstract,
Veriphone, IPQualityScore, AbuseIPDB, Shodan, HIBP, GitHub token) and real
Telegram name/photo lookup. Set via container env (see `server-setups/.env.example`
`OSINT Suite` section) or paste in-app under the **API Keys** tab (persisted
to `/app/data/keys.json`, values never shown back).

### Telegram live lookup (free, 5 min)

Phone scans then show the same name/username/photo Telegram apps show.

```bash
# 1. Get API_ID + API_HASH at https://my.telegram.org (your own account)
# 2. Generate a session string once:
pip install telethon
python -c "
import asyncio
from telethon import TelegramClient
from telethon.sessions import StringSession
async def main():
    async with TelegramClient(StringSession(), int(input('API_ID: ')), input('API_HASH: ')) as c:
        await c.start(phone=input('PHONE (+E164): '))
        print(await c.session.save())
asyncio.run(main())
"
# 3. Set TELEGRAM_API_ID / TELEGRAM_API_HASH / TELEGRAM_SESSION on the container.
# The app imports the number as a contact, reads name/photo, then deletes it.
```

## 🧰 Deep Arsenal (SpiderFoot + HarvestView + PhoneInfoga)

The **Deep Arsenal** tab orchestrates three heavy containers server-side
(deployed via `server-setups/docker-compose.yml` services
`spiderfoot`, `theharvester`, `phoneinfoga` on `dev-backend-network`).
No browser CORS or subpath issues: the suite calls their APIs internally
(`SPIDERFOOT_URL`, `HARVESTVIEW_URL` + `HARVESTVIEW_API_KEY`,
`PHONEINFOGA_URL` envs) and renders results inline.

- **SpiderFoot 4.0** — start full auto scans, poll status, view event-type
  counts + samples. Full graph UI at `https://spider.rajlabs.in`.
- **HarvestView (theHarvester)** — source picker (live from `/api/v1/sources`),
  async runs with status polling. Full desk at `https://harvest.rajlabs.in`.
  Requires `THEHARVESTER_API_KEY` in server `.env` (never in repo).
- **PhoneInfoga v2** — validate + run every scanner for a number inline.
  Full client at `https://phone.rajlabs.in`.
  Note: upstream is stable-but-unmaintained; treated as a deep-scan
  accessory, not a dependency.

The three subdomain UIs sit behind the same Authentik middleware as this app
and need DNS A records (proxied) for `spider`, `harvest`, `phone`.
Until DNS exists, everything is fully usable from the Arsenal tab.
