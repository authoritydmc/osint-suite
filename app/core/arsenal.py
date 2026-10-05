"""Arsenal clients: SpiderFoot, theHarvester HarvestView, PhoneInfoga v2.

All calls are server-side (container network) so browser CORS / subpath
issues never apply. Every helper fails soft with {"error": ...}.
"""
import os

import httpx

SPIDERFOOT_URL = os.getenv("SPIDERFOOT_URL", "http://spiderfoot:5001").rstrip("/")
HARVESTVIEW_URL = os.getenv("HARVESTVIEW_URL", "http://theharvester:8000").rstrip("/")
HARVESTVIEW_API_KEY = os.getenv("HARVESTVIEW_API_KEY", "")
PHONEINFOGA_URL = os.getenv("PHONEINFOGA_URL", "http://phoneinfoga:5000").rstrip("/")

FAST = httpx.Timeout(12.0, connect=5.0)
SLOW = httpx.Timeout(180.0, connect=10.0)


def _err(tool, exc):
    return {"tool": tool, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------- SpiderFoot
async def sf_status():
    try:
        async with httpx.AsyncClient(timeout=FAST) as c:
            r = await c.get(f"{SPIDERFOOT_URL}/scanlist")
            r.raise_for_status()
            scans = r.json()
            running = sum(1 for s in scans if isinstance(s, list) and len(s) > 5 and s[5] == 0)
            return {"tool": "spiderfoot", "ok": True, "reachable": True,
                    "total_scans": len(scans), "running": running}
    except Exception as e:
        return {"tool": "spiderfoot", "ok": False, "reachable": False, **_err("spiderfoot", e)}


async def sf_start_scan(target, name=None):
    """Start a full auto scan. Returns {"scan_id": ...}."""
    try:
        async with httpx.AsyncClient(timeout=FAST) as c:
            r = await c.get(f"{SPIDERFOOT_URL}/startscan", params={
                "scanname": name or f"osint-hub:{target}",
                "scantarget": target,
                "modulelist": "",
                "typelist": "",
                "usecase": "all",
            }, headers={"Accept": "application/json"})
            scan_id = ""
            if r.status_code in (200, 201):
                try:
                    data = r.json()
                    scan_id = data[1] if isinstance(data, list) and len(data) > 1 else str(data)
                except Exception:
                    scan_id = (r.text or "").strip().strip('"')
            elif r.status_code in (301, 302, 303):
                loc = r.headers.get("location", "")
                scan_id = loc.split("id=")[-1] if "id=" in loc else ""
            else:
                r.raise_for_status()
            scan_id = (scan_id or "").strip().strip('"')
            if not scan_id or scan_id.upper().startswith("ERROR"):
                return {"ok": False, "error": f"SpiderFoot refused scan: {(r.text or '')[:200]}"}
            return {"ok": True, "scan_id": scan_id}
    except Exception as e:
        return _err("spiderfoot", e)


async def sf_scans():
    try:
        async with httpx.AsyncClient(timeout=FAST) as c:
            r = await c.get(f"{SPIDERFOOT_URL}/scanlist")
            r.raise_for_status()
            out = []
            for s in r.json():
                # [id, name, target, created, started, status, ...]
                if not isinstance(s, list) or len(s) < 6:
                    continue
                out.append({"id": s[0], "name": s[1], "target": s[2],
                            "created": s[3], "status": "RUNNING" if s[5] == 0 else "FINISHED"})
            return {"ok": True, "scans": out}
    except Exception as e:
        return _err("spiderfoot", e)


def _sf_event(item):
    """SpiderFoot scaneventresults row: [seen, data, src, module, conf, vis,
    risk, hash, ?, ?, type]. Returns normalized dict."""
    import html as _html
    if isinstance(item, dict):
        return {"type": item.get("type", "?"),
                "data": str(item.get("data", ""))[:300],
                "module": item.get("module", "")}
    if isinstance(item, list):
        get = lambda i: item[i] if len(item) > i else ""
        return {"type": str(get(10) or "?"),
                "data": _html.unescape(str(get(1)))[:300],
                "module": str(get(3))}
    return {"type": "?", "data": str(item)[:300], "module": ""}


async def sf_scan_result(scan_id, sample=25):
    """Status + per-type event counts + small sample (capped, never huge)."""
    try:
        async with httpx.AsyncClient(timeout=SLOW) as c:
            st = await c.get(f"{SPIDERFOOT_URL}/scanstatus", params={"id": scan_id})
            st.raise_for_status()
            try:
                sdata = st.json()
                status = sdata[5] if isinstance(sdata, list) and len(sdata) > 5 else sdata
            except Exception:
                status = (st.text or "").strip()
            ev = await c.get(f"{SPIDERFOOT_URL}/scaneventresults",
                             params={"id": scan_id, "eventType": "ALL"})
            ev.raise_for_status()
            events = [_sf_event(e) for e in (ev.json() or [])]
            counts = {}
            for e in events:
                counts[e["type"]] = counts.get(e["type"], 0) + 1
            return {"ok": True, "scan_id": scan_id, "status": status,
                    "total_events": len(events), "counts": counts,
                    "sample": events[:sample]}
    except Exception as e:
        return _err("spiderfoot", e)


# ------------------------------------------------------- theHarvester (HarvestView)
def _hv_headers():
    return {"X-API-Key": HARVESTVIEW_API_KEY} if HARVESTVIEW_API_KEY else {}


async def hv_status():
    if not HARVESTVIEW_API_KEY:
        return {"tool": "harvester", "ok": False, "reachable": False,
                "error": "HARVESTVIEW_API_KEY not configured"}
    try:
        async with httpx.AsyncClient(timeout=FAST) as c:
            r = await c.get(f"{HARVESTVIEW_URL}/api/v1/runs",
                            params={"limit": 1}, headers=_hv_headers())
            if r.status_code == 401:
                return {"tool": "harvester", "ok": False, "reachable": True,
                        "error": "API key rejected (401)"}
            r.raise_for_status()
            return {"tool": "harvester", "ok": True, "reachable": True}
    except Exception as e:
        return {"tool": "harvester", "ok": False, "reachable": False, **_err("harvester", e)}


async def hv_sources():
    try:
        async with httpx.AsyncClient(timeout=FAST) as c:
            r = await c.get(f"{HARVESTVIEW_URL}/api/v1/sources", headers=_hv_headers())
            r.raise_for_status()
            data = r.json()
            # normalize: return raw catalog; UI picks names
            names = []
            if isinstance(data, dict):
                srcs = data.get("sources") or data.get("items") or []
                for s in srcs:
                    if isinstance(s, dict) and s.get("name"):
                        names.append(s["name"])
                    elif isinstance(s, str):
                        names.append(s)
            return {"ok": True, "sources": names, "catalog": data}
    except Exception as e:
        return _err("harvester", e)


async def hv_start_run(target, sources, limit=200):
    try:
        async with httpx.AsyncClient(timeout=FAST) as c:
            r = await c.post(f"{HARVESTVIEW_URL}/api/v1/runs", headers=_hv_headers(),
                             json={"target": target, "sources": sources, "limit": limit})
            r.raise_for_status()
            data = r.json()
            rid = data.get("run_id") or data.get("id") or data.get("runId")
            return {"ok": True, "run_id": rid, "run": data}
    except Exception as e:
        return _err("harvester", e)


async def hv_run(run_id):
    try:
        async with httpx.AsyncClient(timeout=FAST) as c:
            r = await c.get(f"{HARVESTVIEW_URL}/api/v1/runs/{run_id}", headers=_hv_headers())
            r.raise_for_status()
            return {"ok": True, "run": r.json()}
    except Exception as e:
        return _err("harvester", e)


# ------------------------------------------------------------- PhoneInfoga v2
async def pi_status():
    try:
        async with httpx.AsyncClient(timeout=FAST) as c:
            r = await c.get(f"{PHONEINFOGA_URL}/api/")
            r.raise_for_status()
            data = r.json()
            scanners = []
            try:
                s = await c.get(f"{PHONEINFOGA_URL}/api/v2/scanners")
                if s.status_code == 200:
                    scanners = [x.get("name") for x in (s.json().get("scanners") or [])
                                if isinstance(x, dict)]
            except Exception:
                pass
            return {"tool": "phoneinfoga", "ok": True, "reachable": True,
                    "version": data.get("version"), "scanners": scanners}
    except Exception as e:
        return {"tool": "phoneinfoga", "ok": False, "reachable": False, **_err("phoneinfoga", e)}


async def pi_deep_scan(number):
    """Validate + run every scanner. Slow by design (sequential, capped)."""
    out = {"ok": True, "number": number, "validation": None, "results": {}}
    try:
        async with httpx.AsyncClient(timeout=SLOW) as c:
            v = await c.post(f"{PHONEINFOGA_URL}/api/v2/numbers", json={"number": number})
            if v.status_code == 200:
                out["validation"] = v.json()
            s = await c.get(f"{PHONEINFOGA_URL}/api/v2/scanners")
            scanners = [x.get("name") for x in (s.json().get("scanners") or []) if isinstance(x, dict)]
            for name in scanners:
                try:
                    r = await c.post(f"{PHONEINFOGA_URL}/api/v2/scanners/{name}/run",
                                     json={"number": number, "options": {}})
                    out["results"][name] = r.json() if r.status_code == 200 else \
                        {"error": f"HTTP {r.status_code}"}
                except Exception as e:
                    out["results"][name] = {"error": str(e)}
            return out
    except Exception as e:
        return _err("phoneinfoga", e)


async def arsenal_overview():
    import asyncio
    sf, hv, pi = await asyncio.gather(sf_status(), hv_status(), pi_status())
    return {"spiderfoot": sf, "harvester": hv, "phoneinfoga": pi}
