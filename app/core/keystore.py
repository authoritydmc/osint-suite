"""Runtime API-key store: env first, /app/data/keys.json override.

Keys are configurable three ways (precedence: runtime file > env):
  1. Container env (compose / Coolify) — survives rebuilds when set there.
  2. POST /api/settings — persisted to DATA_DIR/keys.json, applied live.
  3. server-setups/.env(.example) documents every supported key.

GET /api/settings never returns values — only which keys are set.
"""
import json
import os
from typing import Dict, Any

DATA_DIR = os.getenv("DATA_DIR", "/app/data")

# key -> (label, where to get it, free?)
REGISTRY: Dict[str, Dict[str, str]] = {
    "NUMVERIFY_KEY": {"label": "Numverify phone validation",
                      "get": "https://numverify.com — free 250 req/mo", "free": "250/mo"},
    "ABSTRACT_PHONE_KEY": {"label": "Abstract phone validation",
                           "get": "https://www.abstractapi.com — free trial", "free": "trial"},
    "VERIPHONE_KEY": {"label": "Veriphone validation",
                      "get": "https://veriphone.io — free quota", "free": "quota"},
    "IPQS_KEY": {"label": "IPQualityScore phone risk",
                 "get": "https://www.ipqualityscore.com — free trial", "free": "trial"},
    "ABUSEIPDB_KEY": {"label": "AbuseIPDB IP reputation",
                      "get": "https://www.abuseipdb.com — free 1000/day", "free": "1000/day"},
    "SHODAN_KEY": {"label": "Shodan host intel",
                   "get": "https://www.shodan.io — free tier", "free": "tier"},
    "HIBP_API_KEY": {"label": "HaveIBeenPwned breaches",
                     "get": "https://haveibeenpwned.com/API/Key — paid", "free": "no"},
    "GITHUB_TOKEN": {"label": "GitHub API (higher rate limits)",
                     "get": "https://github.com/settings/tokens — free", "free": "yes"},
    "TELEGRAM_API_ID": {"label": "Telegram API ID (my.telegram.org)",
                        "get": "https://my.telegram.org — free", "free": "yes"},
    "TELEGRAM_API_HASH": {"label": "Telegram API hash", "get": "https://my.telegram.org — free", "free": "yes"},
    "TELEGRAM_SESSION": {"label": "Telegram session string (generate once, see README)",
                         "get": "local script — free", "free": "yes"},
}


def _path() -> str:
    return os.path.join(DATA_DIR, "keys.json")


def load_runtime_keys() -> Dict[str, str]:
    try:
        with open(_path()) as f:
            data = json.load(f)
        return {k: v for k, v in data.items() if k in REGISTRY and v}
    except Exception:
        return {}


def apply_runtime_keys() -> Dict[str, bool]:
    """Push persisted keys into environ (called at startup + after save)."""
    applied = {}
    for k, v in load_runtime_keys().items():
        os.environ[k] = v
        applied[k] = True
    # re-read module-level key caches that were bound at import time
    try:
        import app.core.email_recon as er
        er.HIBP_KEY = os.getenv("HIBP_API_KEY", "")
    except Exception:
        pass
    try:
        import app.core.phone_recon as pr
        pr.NUMVERIFY_KEY = os.getenv("NUMVERIFY_KEY", "")
        pr.ABSTRACT_KEY = os.getenv("ABSTRACT_PHONE_KEY", "")
        pr.VERIPHONE_KEY = os.getenv("VERIPHONE_KEY", "")
        pr.IPQS_KEY = os.getenv("IPQS_KEY", "")
    except Exception:
        pass
    return applied


def status() -> Dict[str, Any]:
    return {"keys": [
        {"key": k, "label": v["label"], "get": v["get"], "free": v["free"],
         "set": bool(os.getenv(k))}
        for k, v in REGISTRY.items()]}


def save(keys: Dict[str, str]) -> Dict[str, bool]:
    clean = {k: v.strip() for k, v in keys.items() if k in REGISTRY and v and v.strip()}
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        existing: Dict[str, str] = {}
        try:
            with open(_path()) as f:
                existing = json.load(f)
        except Exception:
            pass
        existing.update(clean)
        with open(_path(), "w") as f:
            json.dump(existing, f)
    except Exception:
        pass
    return apply_runtime_keys()
