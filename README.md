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
