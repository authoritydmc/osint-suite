import asyncio
import httpx
from typing import Dict, Any, List

PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{}", "check_url": "https://api.github.com/users/{}", "type": "status_200"},
    {"name": "Twitter / X", "url": "https://x.com/{}", "check_url": "https://x.com/{}", "type": "status_200"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "check_url": "https://www.reddit.com/user/{}/about.json", "type": "reddit"},
    {"name": "Telegram", "url": "https://t.me/{}", "check_url": "https://t.me/{}", "type": "telegram"},
    {"name": "Instagram", "url": "https://instagram.com/{}", "check_url": "https://www.instagram.com/{}/", "type": "status_200"},
    {"name": "Pinterest", "url": "https://pinterest.com/{}", "check_url": "https://pinterest.com/{}/", "type": "status_200"},
    {"name": "Medium", "url": "https://medium.com/@{}", "check_url": "https://medium.com/@{}", "type": "status_200"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "check_url": "https://dev.to/{}", "type": "status_200"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "check_url": "https://gitlab.com/{}", "type": "status_200"},
    {"name": "DockerHub", "url": "https://hub.docker.com/u/{}", "check_url": "https://hub.docker.com/v2/users/{}/", "type": "status_200"},
    {"name": "PyPI", "url": "https://pypi.org/user/{}", "check_url": "https://pypi.org/user/{}/", "type": "status_200"},
    {"name": "NPM", "url": "https://www.npmjs.com/~{}", "check_url": "https://www.npmjs.com/~{}", "type": "status_200"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "check_url": "https://open.spotify.com/user/{}", "type": "status_200"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "check_url": "https://steamcommunity.com/id/{}", "type": "status_200"},
    {"name": "Twitch", "url": "https://twitch.tv/{}", "check_url": "https://twitch.tv/{}", "type": "status_200"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "check_url": "https://soundcloud.com/{}", "type": "status_200"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "check_url": "https://news.ycombinator.com/user?id={}", "type": "hn"},
    {"name": "Replit", "url": "https://replit.com/@{}", "check_url": "https://replit.com/@{}", "type": "status_200"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "check_url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "type": "keybase"},
    {"name": "Gravatar", "url": "https://en.gravatar.com/{}", "check_url": "https://en.gravatar.com/{}.json", "type": "status_200"},
    # --- added: high-value dev/social/video/knowledge platforms ---
    {"name": "StackOverflow", "url": "https://stackoverflow.com/users/{}", "check_url": "https://api.stackexchange.com/2.3/users?inname={}&site=stackoverflow", "type": "so"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "check_url": "https://www.youtube.com/@{}", "type": "status_200"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "check_url": "https://www.tiktok.com/@{}", "type": "status_200"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}", "check_url": "https://www.facebook.com/{}", "type": "status_200"},
    {"name": "Quora", "url": "https://www.quora.com/profile/{}", "check_url": "https://www.quora.com/profile/{}", "type": "status_200"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}", "check_url": "https://www.flickr.com/people/{}", "type": "status_200"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "check_url": "https://vimeo.com/{}", "type": "status_200"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "check_url": "https://dribbble.com/{}", "type": "status_200"},
    {"name": "Behance", "url": "https://www.behance.net/{}", "check_url": "https://www.behance.net/{}", "type": "status_200"},
    {"name": "Codepen", "url": "https://codepen.io/{}", "check_url": "https://codepen.io/{}", "type": "status_200"},
    {"name": "HackerRank", "url": "https://www.hackerrank.com/profile/{}", "check_url": "https://www.hackerrank.com/profile/{}", "type": "status_200"},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{}", "check_url": "https://www.kaggle.com/{}", "type": "status_200"},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{}", "check_url": "https://pastebin.com/u/{}", "type": "status_200"},
    {"name": "Gumroad", "url": "https://{}.gumroad.com", "check_url": "https://{}.gumroad.com", "type": "status_200"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "check_url": "https://www.snapchat.com/add/{}", "type": "status_200"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "check_url": "https://linktr.ee/{}", "type": "status_200"},
]

async def check_single_platform(client: httpx.AsyncClient, username: str, platform: Dict[str, str]) -> Dict[str, Any]:
    url = platform["url"].format(username)
    check_url = platform["check_url"].format(username)
    ptype = platform["type"]
    name = platform["name"]
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    }

    try:
        r = await client.get(check_url, headers=headers, timeout=4.0, follow_redirects=True)
        found = False
        
        if ptype == "status_200":
            found = (r.status_code == 200)
        elif ptype == "reddit":
            found = (r.status_code == 200 and "data" in r.text and "is_suspended" in r.text)
        elif ptype == "telegram":
            found = (r.status_code == 200 and 'extra="tgme_page_extra"' in r.text and "If you have Telegram" in r.text and "not found" not in r.text.lower())
        elif ptype == "hn":
            found = (r.status_code == 200 and f"user: {username}" in r.text)
        elif ptype == "keybase":
            found = (r.status_code == 200 and '"them":[{' in r.text)
        elif ptype == "so":
            try:
                found = (r.status_code == 200 and len(r.json().get("items", [])) > 0)
            except Exception:
                found = False

        extra: Dict[str, Any] = {}
        # Enrich GitHub hits with real profile data (free public API)
        if found and name == "GitHub":
            try:
                g = r.json()
                extra = {"login": g.get("login"), "name": g.get("name"),
                         "bio": (g.get("bio") or "")[:200], "followers": g.get("followers"),
                         "public_repos": g.get("public_repos"), "avatar": g.get("avatar_url"),
                         "blog": g.get("blog"), "location": g.get("location"),
                         "created": g.get("created_at")}
            except Exception:
                pass

        return {
            "platform": name,
            "url": url,
            "exists": found,
            "status_code": r.status_code,
            **({"profile": extra} if extra else {})
        }
    except Exception:
        return {
            "platform": name,
            "url": url,
            "exists": False,
            "status_code": 0
        }

async def search_username(username: str) -> Dict[str, Any]:
    clean_username = username.strip().lower()
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=40)
    async with httpx.AsyncClient(limits=limits) as client:
        tasks = [check_single_platform(client, clean_username, p) for p in PLATFORMS]
        results = await asyncio.gather(*tasks)
        
    found_profiles = [r for r in results if r["exists"]]
    
    return {
        "status": "success",
        "username": clean_username,
        "total_scanned": len(PLATFORMS),
        "total_found": len(found_profiles),
        "profiles": results,
        "found_profiles": found_profiles
    }
