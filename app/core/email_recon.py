"""Email recon: Holehe live account check, Gravatar, GitHub commits, HIBP.

Holehe (https://github.com/megadose/holehe) checks 100+ sites for real —
no keys, ~10s. Everything else is best-effort.
"""
import asyncio
import hashlib
import httpx
import os
from typing import Dict, Any

HIBP_KEY = os.getenv("HIBP_API_KEY", "")


async def holehe_check(email: str, timeout_s: int = 60) -> Dict[str, Any]:
    """Run real Holehe modules; return registered-site list (never raises)."""
    try:
        from holehe.core import import_submodules, get_functions, launch_module
        import holehe.modules
    except Exception as e:
        return {"available": False, "error": f"holehe not installed: {e}"}
    try:
        websites = get_functions(import_submodules(holehe.modules))

        async def run():
            out: list = []
            async with httpx.AsyncClient() as client:
                await asyncio.gather(*[launch_module(m, email, client, out)
                                       for m in websites])
            return out

        found = await asyncio.wait_for(run(), timeout=timeout_s)
        reg = sorted({d.get("name") for d in found if d.get("exists")})
        return {"available": True, "sites_checked": len(found),
                "registered_count": len(reg), "registered_on": reg}
    except Exception as e:
        return {"available": True, "error": str(e)[:300]}


async def analyze_email(raw_email: str) -> Dict[str, Any]:
    email = raw_email.strip().lower()
    out: Dict[str, Any] = {"email": email, "valid_format": "@" in email and "." in email.split("@")[-1],
                           "gravatar": {}, "github_commits": {}, "hibp": {}, "lookups": []}
    if not out["valid_format"]:
        out["status"] = "invalid_format"
        return out

    user, _, domain = email.partition("@")
    mh = hashlib.md5(email.encode()).hexdigest()  # Gravatar uses MD5 (their design)
    timeout = httpx.Timeout(8.0)
    async with httpx.AsyncClient(timeout=timeout,
                                 headers={"User-Agent": "RajLabs-OSINT/2.0"}) as c:
        # 1. Gravatar profile (free, no key)
        try:
            r = await c.get(f"https://en.gravatar.com/{mh}.json")
            if r.status_code == 200:
                e = (r.json().get("entry") or [{}])[0]
                out["gravatar"] = {"exists": True, "name": e.get("displayName"),
                    "profile": e.get("profileUrl"),
                    "avatar": f"https://www.gravatar.com/avatar/{mh}?d=404"}
            else:
                a = await c.get(f"https://www.gravatar.com/avatar/{mh}?d=404")
                out["gravatar"] = {"exists": a.status_code == 200,
                    "avatar": f"https://www.gravatar.com/avatar/{mh}?d=404" if a.status_code == 200 else None}
        except Exception:
            pass
        # 2. GitHub commits authored by this email (free public search API)
        try:
            r = await c.get("https://api.github.com/search/commits",
                            params={"q": f"author-email:{email}", "per_page": 5},
                            headers={"Accept": "application/vnd.github.cloak-preview"})
            if r.status_code == 200:
                j = r.json()
                out["github_commits"] = {"total": j.get("total_count", 0),
                    "repos": sorted({i.get("repository", {}).get("full_name", "?")
                                     for i in j.get("items", [])})[:10]}
            elif r.status_code in (401, 403, 429):
                out["github_commits"] = {"note": "rate-limited — retry later or add GITHUB_TOKEN"}
        except Exception:
            pass
        # 3. HaveIBeenPwned (requires free API key)
        if HIBP_KEY:
            try:
                r = await c.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                                params={"truncateResponse": "true"},
                                headers={"hibp-api-key": HIBP_KEY})
                if r.status_code == 200:
                    out["hibp"] = {"breached": True, "breaches": r.json()}
                elif r.status_code == 404:
                    out["hibp"] = {"breached": False}
            except Exception:
                pass
        else:
            out["hibp"] = {"note": "set HIBP_API_KEY for breach lookup"}

    local, dom = user, domain
    out["holehe"] = await holehe_check(email)
    out["lookups"] = [
        {"name": "Epieos Email Lookup", "url": "https://epieos.com/"},
        {"name": "Gravatar Profile", "url": f"https://en.gravatar.com/{mh}"},
        {"name": "GitHub Commits", "url": f"https://github.com/search?q=author-email%3A{email}&type=commits"},
        {"name": "Google Dork", "url": f"https://www.google.com/search?q=\"{email}\""},
        {"name": "Domain Accounts Guess", "url": f"https://www.google.com/search?q=\"{local}\"+site%3A{dom}"},
    ]
    out["status"] = "success"
    return out
