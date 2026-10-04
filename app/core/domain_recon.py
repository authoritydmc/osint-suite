import dns.resolver
import httpx
import socket
from typing import Dict, Any, List

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
            
    # Subdomain quick scan
    common_subdomains = ["www", "mail", "api", "admin", "auth", "dev", "status", "app", "vpn", "portal", "cloud"]
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
        "external_tools": [
            {"name": "SecurityTrails", "url": f"https://securitytrails.com/domain/{clean_domain}/dns"},
            {"name": "CRT.sh Cert Transparency", "url": f"https://crt.sh/?q={clean_domain}"},
            {"name": "DNSDumpster", "url": f"https://dnsdumpster.com/"},
            {"name": "VirusTotal Domain", "url": f"https://www.virustotal.com/gui/domain/{clean_domain}"}
        ]
    }

async def ip_intel(ip_or_host: str) -> Dict[str, Any]:
    target = ip_or_host.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target

    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"https://ipapi.co/{ip}/json/", timeout=5.0)
            if r.status_code == 200:
                data = r.json()
                return {
                    "ip": ip,
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "country_code": data.get("country_code", "Unknown"),
                    "asn": data.get("asn", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "timezone": data.get("timezone", "Unknown"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude")
                }
        except Exception:
            pass

    return {"ip": ip, "status": "intel_unavailable"}
