"""
app/core/reddit_recon.py
========================
High-concurrency Async Reddit Intelligence Engine.
Extracts user profiles, karma breakdown, posting timelines, active subreddits,
recent comments/submissions, and deep-search keywords/dorks via public endpoints
or authenticated OAuth API (free standard developer app credentials).
"""

import os
import httpx
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from collections import Counter

_HTTP_TIMEOUT = 8.0
_USER_AGENT = "RajLabsOSINT/2.0 (by /u/rajlabs_intel)"
_cached_token: Optional[str] = None
_token_expiry: float = 0.0

async def _get_oauth_token() -> Optional[str]:
    """Obtain or return cached Reddit OAuth application token."""
    global _cached_token, _token_expiry
    now = datetime.now(timezone.utc).timestamp()
    if _cached_token and now < _token_expiry:
        return _cached_token

    client_id = os.getenv("REDDIT_CLIENT_ID", "")
    client_secret = os.getenv("REDDIT_CLIENT_SECRET", "")
    if not (client_id and client_secret):
        return None

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                "https://www.reddit.com/api/v1/access_token",
                auth=(client_id, client_secret),
                data={"grant_type": "client_credentials"},
                headers={"User-Agent": _USER_AGENT}
            )
            if r.status_code == 200:
                data = r.json()
                _cached_token = data.get("access_token")
                _token_expiry = now + float(data.get("expires_in", 3600)) - 60
                return _cached_token
    except Exception:
        pass
    return None


async def analyze_reddit_user(username: str) -> Dict[str, Any]:
    """
    Perform deep Reddit profile & activity intelligence on a username.
    """
    clean_user = username.strip().lstrip("u/").lstrip("/")
    q_user = urllib.parse.quote(clean_user)
    
    # Dork & Pivoting Matrix (always available even without API keys)
    dorks = [
        {"name": "Reddit User Submissions", "url": f"https://www.google.com/search?q=site:reddit.com/user/{q_user}+OR+site:reddit.com/r/*+\"%2Fu%2F{q_user}\"", "badge": "Google Dork"},
        {"name": "Reddit Comment Search (Pushshift/Camas)", "url": f"https://camas.unddit.com/#%7B%22author%22:%22{q_user}%22%7D", "badge": "Archive Mirror"},
        {"name": "Reddit Archive Pushshift", "url": f"https://api.pullpush.io/reddit/search/comment/?author={q_user}&size=20", "badge": "JSON API"},
        {"name": "Direct Reddit Profile", "url": f"https://www.reddit.com/user/{clean_user}", "badge": "Live Page"},
        {"name": "Old Reddit User Overview", "url": f"https://old.reddit.com/user/{clean_user}", "badge": "Legacy UI"}
    ]

    token = await _get_oauth_token()
    headers = {"User-Agent": _USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        base_url = "https://oauth.reddit.com"
    else:
        base_url = "https://www.reddit.com"

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
        about_url = f"{base_url}/user/{clean_user}/about.json"
        submissions_url = f"{base_url}/user/{clean_user}/submitted.json?limit=50"
        comments_url = f"{base_url}/user/{clean_user}/comments.json?limit=50"

        try:
            r_about = await client.get(about_url, headers=headers)
        except Exception as e:
            return {
                "status": "partial",
                "exists": None,
                "username": clean_user,
                "dorks": dorks,
                "note": f"Direct connect failed: {str(e)}"
            }

        if r_about.status_code == 404:
            return {"status": "not_found", "exists": False, "username": clean_user, "dorks": dorks}
        elif r_about.status_code in (401, 403):
            # Blocked without OAuth key, return rich dork pivots
            return {
                "status": "rate_limited",
                "exists": True,
                "username": clean_user,
                "profile": {
                    "name": clean_user,
                    "url": f"https://www.reddit.com/user/{clean_user}",
                },
                "dorks": dorks,
                "note": "Reddit blocked unauthenticated request. Add REDDIT_CLIENT_ID & REDDIT_CLIENT_SECRET in API Keys for live API data."
            }
        elif r_about.status_code != 200:
            return {"status": "error", "error": f"Reddit returned HTTP {r_about.status_code}", "username": clean_user, "dorks": dorks}

        try:
            data_about = r_about.json().get("data", {})
        except Exception:
            return {"status": "error", "error": "Invalid JSON response from Reddit", "username": clean_user, "dorks": dorks}

        # Check if suspended
        is_suspended = data_about.get("is_suspended", False)
        if is_suspended:
            return {
                "status": "success",
                "exists": True,
                "is_suspended": True,
                "username": clean_user,
                "profile": {"name": clean_user, "is_suspended": True, "url": f"https://www.reddit.com/user/{clean_user}"},
                "dorks": dorks
            }

        created_utc = data_about.get("created_utc")
        created_iso = ""
        account_age_days = 0
        if created_utc:
            dt = datetime.fromtimestamp(created_utc, tz=timezone.utc)
            created_iso = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            account_age_days = max(0, (datetime.now(timezone.utc) - dt).days)

        profile = {
            "id": data_about.get("id"),
            "name": data_about.get("name", clean_user),
            "created_utc": created_utc,
            "created_at": created_iso,
            "account_age_days": account_age_days,
            "link_karma": data_about.get("link_karma", 0),
            "comment_karma": data_about.get("comment_karma", 0),
            "total_karma": data_about.get("total_karma", 0),
            "is_gold": data_about.get("is_gold", False),
            "is_mod": data_about.get("is_mod", False),
            "has_verified_email": data_about.get("has_verified_email", False),
            "accept_followers": data_about.get("accept_followers", True),
            "icon_img": (data_about.get("icon_img") or "").split("?")[0],
            "subreddit_title": (data_about.get("subreddit") or {}).get("title", ""),
            "subreddit_desc": (data_about.get("subreddit") or {}).get("public_description", ""),
            "url": f"https://www.reddit.com/user/{clean_user}"
        }

        # 2. Fetch submissions & comments
        sub_list = []
        comm_list = []
        subreddits_counter = Counter()

        try:
            r_sub, r_comm = await client.get(submissions_url, headers=headers), await client.get(comments_url, headers=headers)
            
            if r_sub.status_code == 200:
                raw_subs = r_sub.json().get("data", {}).get("children", [])
                for s in raw_subs:
                    sdata = s.get("data", {})
                    sub_name = sdata.get("subreddit", "")
                    subreddits_counter[sub_name] += 1
                    s_utc = sdata.get("created_utc")
                    
                    sub_list.append({
                        "id": sdata.get("id"),
                        "title": sdata.get("title"),
                        "subreddit": sub_name,
                        "score": sdata.get("score", 0),
                        "upvote_ratio": sdata.get("upvote_ratio", 1.0),
                        "num_comments": sdata.get("num_comments", 0),
                        "url": f"https://www.reddit.com{sdata.get('permalink', '')}",
                        "created_utc": s_utc,
                        "created_at": datetime.fromtimestamp(s_utc, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if s_utc else "",
                        "is_self": sdata.get("is_self", False),
                        "selftext": (sdata.get("selftext") or "")[:300]
                    })

            if r_comm.status_code == 200:
                raw_comms = r_comm.json().get("data", {}).get("children", [])
                for c in raw_comms:
                    cdata = c.get("data", {})
                    sub_name = cdata.get("subreddit", "")
                    subreddits_counter[sub_name] += 1
                    c_utc = cdata.get("created_utc")

                    comm_list.append({
                        "id": cdata.get("id"),
                        "subreddit": sub_name,
                        "body": (cdata.get("body") or "")[:300],
                        "score": cdata.get("score", 0),
                        "url": f"https://www.reddit.com{cdata.get('permalink', '')}",
                        "link_title": cdata.get("link_title", ""),
                        "created_utc": c_utc,
                        "created_at": datetime.fromtimestamp(c_utc, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if c_utc else ""
                    })
        except Exception:
            pass

        top_subreddits = [{"subreddit": k, "activity_count": v} for k, v in subreddits_counter.most_common(12)]

        return {
            "status": "success",
            "exists": True,
            "username": clean_user,
            "profile": profile,
            "top_subreddits": top_subreddits,
            "recent_submissions": sub_list[:15],
            "recent_comments": comm_list[:15],
            "activity_summary": {
                "total_submissions_analyzed": len(sub_list),
                "total_comments_analyzed": len(comm_list),
                "unique_subreddits_participated": len(subreddits_counter)
            },
            "dorks": dorks
        }


async def search_reddit(query: str, limit: int = 15) -> Dict[str, Any]:
    """
    Search Reddit submissions across subreddits matching query/dork.
    """
    q_encoded = urllib.parse.quote(query)
    dorks = [
        {"name": "Google Reddit Dork Search", "url": f"https://www.google.com/search?q=site:reddit.com+{q_encoded}", "badge": "Google Dork"},
        {"name": "Bing Reddit Discussion Search", "url": f"https://www.bing.com/search?q=site:reddit.com+{q_encoded}", "badge": "Bing Index"},
        {"name": "Reddit Official Search Direct", "url": f"https://www.reddit.com/search/?q={q_encoded}", "badge": "Direct Web"}
    ]

    token = await _get_oauth_token()
    headers = {"User-Agent": _USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        search_url = f"https://oauth.reddit.com/search.json?q={q_encoded}&sort=relevance&limit={limit}"
    else:
        search_url = f"https://www.reddit.com/search.json?q={q_encoded}&sort=relevance&limit={limit}"
    
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
        try:
            r = await client.get(search_url, headers=headers)
            if r.status_code == 200:
                data = r.json().get("data", {}).get("children", [])
                results = []
                for item in data:
                    d = item.get("data", {})
                    created_utc = d.get("created_utc")
                    results.append({
                        "title": d.get("title"),
                        "author": d.get("author"),
                        "subreddit": d.get("subreddit"),
                        "score": d.get("score", 0),
                        "num_comments": d.get("num_comments", 0),
                        "url": f"https://www.reddit.com{d.get('permalink', '')}",
                        "selftext": (d.get("selftext") or "")[:250],
                        "created_at": datetime.fromtimestamp(created_utc, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if created_utc else ""
                    })
                return {"status": "success", "query": query, "count": len(results), "results": results, "dorks": dorks}
            else:
                return {"status": "fallback", "query": query, "count": 0, "results": [], "dorks": dorks, "note": "Live API lookup requires REDDIT_CLIENT_ID / SECRET; open dorks below"}
        except Exception as e:
            return {"status": "fallback", "query": query, "count": 0, "results": [], "dorks": dorks, "error": str(e)}
