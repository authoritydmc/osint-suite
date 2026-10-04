from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
import os

# When "1" (default), every request except /health and /docs must carry
# Authentik ForwardAuth identity headers (X-authentik-username/email).
# Traefik enforces login at the edge; this is defense-in-depth so direct
# container access (bypassing the proxy) cannot be abused.
REQUIRE_SSO = os.getenv("REQUIRE_AUTHENTIK_SSO", "1") == "1"
PUBLIC_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}

from app.core.phone_recon import analyze_phone_number
from app.core.sherlock_recon import search_username
from app.core.domain_recon import query_dns_records, ip_intel

app = FastAPI(
    title="RajLabs OSINT & NUMINT Suite",
    description="Enterprise Multi-Vector Threat Intelligence, Phone Recon & Social Reconnaissance Engine",
    version="1.0.0"
)

templates = Jinja2Templates(directory="app/templates")

def get_sso_user(request: Request) -> str | None:
    """Return Authentik SSO identity from trusted ForwardAuth headers."""
    return request.headers.get("X-authentik-username") or request.headers.get("X-authentik-email")

class AuthentikSSOMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if REQUIRE_SSO and request.url.path not in PUBLIC_PATHS:
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

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html")

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "osint-suite", "version": "1.0.0"}

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
    return analyze_phone_number(req.phone, req.country_code)

@app.post("/api/recon/username")
async def api_username(req: UsernameRequest):
    return await search_username(req.username)

@app.post("/api/recon/domain")
async def api_domain(req: DomainRequest):
    return query_dns_records(req.domain)

@app.post("/api/recon/ip")
async def api_ip(req: IPRequest):
    return await ip_intel(req.ip)
