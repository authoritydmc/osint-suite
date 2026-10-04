import dns.resolver
import httpx
import os
import socket
from typing import Dict, Any, List

# HackerTarget free tier: ~50 calls/day, 2 req/s. Guarded + best-effort.
HT_BASE = "https://api.hackertarget.com"

SUBDOMAIN_WORDLIST = ["www", "mail", "api", "admin", "auth", "dev", "status",
    "app", "vpn", "portal", "cloud", "blog", "shop", "cdn", "static", "assets",
    "beta", "staging", "test", "demo", "support", "help", "docs", "git", "ci",
    "jenkins", "jira", "grafana", "prometheus", "kibana", "db", "sql", "ftp",
    "smtp", "imap", "pop", "mx", "ns1", "ns2", "dns", "ntp", "proxy", "gateway",
    "sso", "login", "account", "billing", "pay", "checkout", "crm", "erp",
    "hr", "wiki", "forum", "chat", "meet", "video", "stream", "mobile", "m",
    "secure", "private", "internal", "intranet", "remote", "office", "corp",
    "partner", "client", "dashboard", "panel", "console", "manage", "ops"]

def _typo_permutations(domain: str) -> List[str]:
    """Cheap local typosquat candidates (dnstwist-style, no dependency)."""
    if "." not in domain:
        return []
    name, _, tld = domain.partition(".")
    out = set()
    for i in range(len(name)):
        out.add(name[:i] + name[i + 1:] + "." + tld)          # omission
        if i < len(name) - 1:
            out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:] + "." + tld)  # swap
    for c in ("1", "0", "-"):
        out.add(name + c + "." + tld)                           # suffix
    out.add("get" + name + "." + tld)
    out.add(name + "app." + tld)
    return sorted(out - {domain})[:30]

def query_dns_records(domain: str) -> Dict[str, Any]:
    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    records: Dict[str, List[str]] = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": [],
        "SOA": []
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    for rtype in records.keys():
        try:
            answers = resolver.resolve(clean_domain, rtype)
            for rdata in answers:
                records[rtype].append(str(rdata))
        except Exception:
            pass
            
    # Check Cloudflare & Security headers
    is_behind_cloudflare = False
    for ns in records.get("NS", []):
        if "cloudflare.com" in ns.lower():
            is_behind_cloudflare = True
            
    # Subdomain quick scan (expanded wordlist)
    common_subdomains = SUBDOMAIN_WORDLIST
    found_subdomains = []
    for sub in common_subdomains:
        fqdn = f"{sub}.{clean_domain}"
        try:
            ans = resolver.resolve(fqdn, "A")
            ips = [str(r) for r in ans]
            found_subdomains.append({"subdomain": fqdn, "ips": ips})
        except Exception:
            pass

    return {
        "domain": clean_domain,
        "dns_records": records,
        "is_behind_cloudflare": is_behind_cloudflare,
        "discovered_subdomains": found_subdomains,
        "typosquat_candidates": _typo_permutations(clean_domain),
        "external_tools": [
            {"name": "SecurityTrails", "url": f"https://securitytrails.com/domain/{clean_domain}/dns"},
            {"name": "CRT.sh Cert Transparency", "url": f"https://crt.sh/?q={clean_domain}"},
            {"name": "DNSDumpster", "url": f"https://dnsdumpster.com/"},
            {"name": "VirusTotal Domain", "url": f"https://www.virustotal.com/gui/domain/{clean_domain}"}
        ]
    }

async def enrich_domain(clean_domain: str) -> Dict[str, Any]:
    """Passive web intel — all free, no keys (best-effort, never raises)."""
    out: Dict[str, Any] = {"crtsh_certs": [], "urlscan": {}, "hackertarget": {},
                           "rdap": {}, "web_presence": {}, "security_headers": {}}
    timeout = httpx.Timeout(8.0)
    async with httpx.AsyncClient(timeout=timeout,
                                 headers={"User-Agent": "RajLabs-OSINT/2.0"}) as c:
        # 1. Certificate Transparency (crt.sh — free, generous)
        try:
            r = await c.get("https://crt.sh/", params={"q": f"%.{clean_domain}", "output": "json"})
            if r.status_code == 200:
                seen = set()
                for cert in r.json():
                    n = cert.get("name_value", "")
                    if n and n not in seen:
                        seen.add(n)
                        out["crtsh_certs"].append({"name": n, "issuer": cert.get("issuer_name"),
                                                  "not_before": cert.get("not_before")})
                    if len(out["crtsh_certs"]) >= 25:
                        break
        except Exception:
            pass
        # 2. urlscan.io historical scans (free search, ~1000/day)
        try:
            r = await c.get("https://urlscan.io/api/v1/search/",
                            params={"q": f"domain:{clean_domain}", "size": 5})
            if r.status_code == 200:
                j = r.json()
                out["urlscan"] = {"total": j.get("total", 0),
                    "scans": [{"url": s.get("task", {}).get("url"),
                               "time": s.get("task", {}).get("time")}
                              for s in j.get("results", [])]}
        except Exception:
            pass
        # 3. HackerTarget passive set (free ~50/day — failures are normal)
        for tool, key in (("hostsearch", "subdomains"), ("reverseiplookup", "shared_hosts"),
                          ("whois", "whois")):
            try:
                r = await c.get(f"{HT_BASE}/{tool}/", params={"q": clean_domain})
                if r.status_code == 200 and "error" not in r.text.lower()[:60]:
                    out["hackertarget"][key] = r.text.strip().split("\n")[:30]
            except Exception:
                pass
        # 4. RDAP registration (free, no key)
        try:
            tld = clean_domain.rsplit(".", 1)[-1]
            boot = await c.get("https://data.iana.org/rdap/dns")
            srv = None
            if boot.status_code == 200:
                for s in boot.json().get("services", []):
                    if tld in s[0]:
                        srv = s[1][0]
                        break
            if srv:
                r = await c.get(f"{srv}domain/{clean_domain}")
                if r.status_code == 200:
                    j = r.json()
                    out["rdap"] = {"registrar": str([e.get("vcardArray", []) for e in j.get("entities", [])])[:300],
                        "created": str(j.get("events", ""))[:300], "status": j.get("status")}
        except Exception:
            pass
        # 5. Web presence: site fetch + security.txt/robots/sitemap + headers
        for scheme in ("https://", "http://"):
            try:
                r = await c.get(scheme + clean_domain, follow_redirects=True)
                if r.status_code < 400:
                    h = {k.lower(): v for k, v in r.headers.items()}
                    out["web_presence"] = {"url": str(r.url), "status": r.status_code,
                        "server": h.get("server"), "powered_by": h.get("x-powered-by"),
                        "title": _page_title(r.text)}
                    missing = [x for x in ("strict-transport-security", "content-security-policy",
                        "x-frame-options", "x-content-type-options", "referrer-policy")
                        if x not in h]
                    out["security_headers"] = {"missing": missing,
                        "grade": "A" if not missing else ("B" if len(missing) <= 2 else "F")}
                    break
            except Exception:
                continue
        for path in ("/.well-known/security.txt", "/robots.txt", "/sitemap.xml"):
            for scheme in ("https://", "http://"):
                try:
                    r = await c.get(scheme + clean_domain + path)
                    if r.status_code == 200 and len(r.text) < 20000:
                        out["web_presence"][path.strip("/.").replace("/", "_")] = r.text[:2000]
                        break
                except Exception:
                    pass
    return out


def _page_title(html: str) -> str:
    try:
        low = html.lower()
        i = low.index("<title>") + 7
        return html[i:i + 120].split("</title>")[0].strip()
    except Exception:
        return ""


async def ip_intel(ip_or_host: str) -> Dict[str, Any]:
    target = ip_or_host.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target

    result: Dict[str, Any] = {"ip": ip}
    found = False
    # Provider chain: ipapi.co (1000/day) -> ip-api.com (45/min, HTTP free tier)
    # -> ipwho.is (free HTTPS, no key). First success wins; fields normalized.
    async with httpx.AsyncClient(timeout=6.0) as client:
        try:
            r = await client.get(f"https://ipapi.co/{ip}/json/")
            if r.status_code == 200 and "error" not in r.text.lower()[:80]:
                d = r.json()
                result.update({"city": d.get("city", "Unknown"), "region": d.get("region", "Unknown"),
                    "country": d.get("country_name", "Unknown"), "country_code": d.get("country_code", "Unknown"),
                    "asn": d.get("asn", "Unknown"), "org": d.get("org", "Unknown"),
                    "timezone": d.get("timezone", "Unknown"), "latitude": d.get("latitude"),
                    "longitude": d.get("longitude"), "geo_source": "ipapi.co"})
                found = True
        except Exception:
            pass
        if not found:
            try:
                r = await client.get(f"http://ip-api.com/json/{ip}",
                                    params={"fields": "status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as"})
                d = r.json()
                if d.get("status") == "success":
                    result.update({"city": d.get("city", "Unknown"), "region": d.get("regionName", "Unknown"),
                        "country": d.get("country", "Unknown"), "country_code": d.get("countryCode", "Unknown"),
                        "asn": d.get("as", "Unknown"), "org": d.get("org") or d.get("isp", "Unknown"),
                        "timezone": d.get("timezone", "Unknown"), "latitude": d.get("lat"),
                        "longitude": d.get("lon"), "geo_source": "ip-api.com"})
                    found = True
            except Exception:
                pass
        if not found:
            try:
                r = await client.get(f"https://ipwho.is/{ip}")
                d = r.json()
                if d.get("success", True):
                    result.update({"city": d.get("city", "Unknown"), "region": d.get("region", "Unknown"),
                        "country": d.get("country", "Unknown"), "country_code": d.get("country_code", "Unknown"),
                        "asn": str(d.get("connection", {}).get("asn", "Unknown")),
                        "org": d.get("connection", {}).get("org", "Unknown"),
                        "timezone": str(d.get("timezone", {}).get("id", "Unknown")),
                        "latitude": d.get("latitude"), "longitude": d.get("longitude"),
                        "geo_source": "ipwho.is"})
                    found = True
            except Exception:
                pass
        # HackerTarget infra set (passive, free tier) + optional keyed sources
        infra: Dict[str, Any] = {}
        for tool, key in (("reversedns", "ptr"), ("reverseiplookup", "shared_hosts"),
                           ("aslookup", "asn_info")):
            try:
                r = await client.get(f"{HT_BASE}/{tool}/", params={"q": ip})
                if r.status_code == 200 and "error" not in r.text.lower()[:60]:
                    infra[key] = r.text.strip().split("\n")[:20]
            except Exception:
                pass
        abkey = os.getenv("ABUSEIPDB_KEY", "")
        if abkey:
            try:
                r = await client.get("https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": abkey, "Accept": "application/json"})
                d = r.json().get("data", {})
                infra["abuseipdb"] = {"score": d.get("abuseConfidenceScore"),
                    "reports": d.get("totalReports"), "country": d.get("countryCode")}
            except Exception:
                pass
        shkey = os.getenv("SHODAN_KEY", "")
        if shkey:
            try:
                r = await client.get(f"https://api.shodan.io/shodan/host/{ip}",
                                     params={"key": shkey})
                d = r.json()
                infra["shodan"] = {"ports": d.get("ports"), "os": d.get("os"),
                    "org": d.get("org"), "tags": d.get("tags")}
            except Exception:
                pass
        if infra:
            result["infra"] = infra

    if not found and "infra" not in result:
        return {"ip": ip, "status": "intel_unavailable"}
    return result
