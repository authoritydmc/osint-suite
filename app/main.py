from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import Dict
import os

# When "1" (default), every request except /health and /docs must carry
# Authentik ForwardAuth identity headers (X-authentik-username/email).
# Traefik enforces login at the edge; this is defense-in-depth so direct
# container access (bypassing the proxy) cannot be abused.
REQUIRE_SSO = os.getenv("REQUIRE_AUTHENTIK_SSO", "1") == "1"
# /health + /static/* stay public: Authentik fetches app icons without SSO
# headers, and browsers load favicons/assets unauthenticated.
PUBLIC_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}
PUBLIC_PREFIXES = ("/static/",)

from app.core.phone_recon import analyze_phone_number
from app.core.sherlock_recon import search_username
from app.core.domain_recon import query_dns_records, enrich_domain, ip_intel
from app.core.email_recon import analyze_email
from app.core.identity_recon import telegram_lookup_e164, telegram_status
from app.core.reddit_recon import analyze_reddit_user, search_reddit
from app.core import keystore
from app.core import arsenal

keystore.apply_runtime_keys()  # persisted /api/settings keys -> environ

app = FastAPI(
    title="RajLabs OSINT & NUMINT Suite",
    description="Enterprise Multi-Vector Threat Intelligence, Phone Recon & Social Reconnaissance Engine",
    version="2.0.0"
)

templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

def get_sso_user(request: Request) -> str | None:
    """Return Authentik SSO identity from trusted ForwardAuth headers."""
    return request.headers.get("X-authentik-username") or request.headers.get("X-authentik-email")

class AuthentikSSOMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if REQUIRE_SSO and request.url.path not in PUBLIC_PATHS and not request.url.path.startswith(PUBLIC_PREFIXES):
            if not get_sso_user(request):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized. Authentik SSO login required."},
                )
        request.state.sso_user = get_sso_user(request)
        return await call_next(request)

app.add_middleware(AuthentikSSOMiddleware)

class PhoneRequest(BaseModel):
    phone: str
    country_code: str = "IN"

class UsernameRequest(BaseModel):
    username: str

class DomainRequest(BaseModel):
    domain: str

class IPRequest(BaseModel):
    ip: str

class EmailRequest(BaseModel):
    email: str

class RedditUserRequest(BaseModel):
    username: str

class RedditSearchRequest(BaseModel):
    query: str
    limit: int = 15

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html")

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "osint-suite", "version": "2.0.0"}

@app.get("/api/client-geo")
async def get_client_geo(request: Request):
    cf_country = request.headers.get("CF-IPCountry")
    client_ip = (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP")
        or request.client.host
    )
    
    if cf_country and len(cf_country) == 2:
        return {
            "client_ip": client_ip,
            "country_code": cf_country.upper(),
            "country": cf_country.upper(),
            "source": "cloudflare-header"
        }
    
    intel = await ip_intel(client_ip)
    cc = intel.get("country_code", "IN")
    cname = intel.get("country", "India")
    return {
        "client_ip": client_ip,
        "country_code": cc if cc else "IN",
        "country": cname if cname else "India",
        "source": "ip-intel"
    }

@app.post("/api/recon/phone")
async def api_phone(req: PhoneRequest):
    res = await analyze_phone_number(req.phone, req.country_code)
    try:
        e164 = (res.get("number_details") or {}).get("e164", "")
        if e164:
            res["telegram"] = await telegram_lookup_e164(e164)
    except Exception:
        pass
    return res

@app.post("/api/recon/username")
async def api_username(req: UsernameRequest):
    return await search_username(req.username)

@app.post("/api/recon/domain")
async def api_domain(req: DomainRequest):
    base = query_dns_records(req.domain)
    try:
        base["passive_intel"] = await enrich_domain(base["domain"])
    except Exception as e:
        base["passive_intel"] = {"error": str(e)}
    return base

@app.post("/api/recon/email")
async def api_email(req: EmailRequest):
    return await analyze_email(req.email)

@app.post("/api/recon/reddit/user")
async def api_reddit_user(req: RedditUserRequest):
    return await analyze_reddit_user(req.username)

@app.post("/api/recon/reddit/search")
async def api_reddit_search(req: RedditSearchRequest):
    return await search_reddit(req.query, req.limit)


class SettingsSave(BaseModel):
    keys: Dict[str, str]


@app.get("/api/settings")
async def api_settings_get():
    return {**keystore.status(), "telegram": telegram_status()}


@app.post("/api/settings")
async def api_settings_save(req: SettingsSave):
    return {"applied": keystore.save(req.keys), **keystore.status()}

@app.post("/api/recon/ip")
async def api_ip(req: IPRequest):
    return await ip_intel(req.ip)


class SFScanRequest(BaseModel):
    target: str
    name: str = ""


class HVRunRequest(BaseModel):
    target: str
    sources: list = []
    limit: int = 200


class PIDeepRequest(BaseModel):
    phone: str


@app.get("/api/arsenal/status")
async def api_arsenal_status():
    return await arsenal.arsenal_overview()


@app.post("/api/arsenal/spiderfoot/scan")
async def api_sf_scan(req: SFScanRequest):
    return await arsenal.sf_start_scan(req.target.strip(), req.name.strip() or None)


@app.get("/api/arsenal/spiderfoot/scans")
async def api_sf_scans():
    return await arsenal.sf_scans()


@app.get("/api/arsenal/spiderfoot/scan/{scan_id}")
async def api_sf_scan_one(scan_id: str):
    return await arsenal.sf_scan_result(scan_id)


@app.get("/api/arsenal/harvester/sources")
async def api_hv_sources():
    return await arsenal.hv_sources()


@app.post("/api/arsenal/harvester/run")
async def api_hv_run(req: HVRunRequest):
    return await arsenal.hv_start_run(req.target.strip(), req.sources, req.limit)


@app.get("/api/arsenal/harvester/run/{run_id}")
async def api_hv_run_one(run_id: str):
    return await arsenal.hv_run(run_id)


@app.post("/api/arsenal/phone/deep")
async def api_pi_deep(req: PIDeepRequest):
    return await arsenal.pi_deep_scan(req.phone.strip())
