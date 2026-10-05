"""
Test verification script for RajLabs OSINT & NUMINT Intelligence Suite.
Tests all intelligence endpoints and verify responses.
"""
import sys
import os
import asyncio
from fastapi.testclient import TestClient

# Ensure repo is on sys.path
sys.path.insert(0, "/home/ubuntu/osint-suite")

# Disable REQUIRE_AUTHENTIK_SSO for local test runner
os.environ["REQUIRE_AUTHENTIK_SSO"] = "0"
os.environ["DATA_DIR"] = "/tmp/osint-data"

from app.main import app

client = TestClient(app)

def run_tests():
    print("=== 🛰️ STARTING OSINT SUITE VERIFICATION ===")
    
    # 1. Health check
    r = client.get("/health")
    assert r.status_code == 200, f"Health check failed: {r.text}"
    print("✅ [1/8] /health: PASS", r.json())

    # 2. Phone NUMINT
    r = client.post("/api/recon/phone", json={"phone": "+919876543210", "country_code": "IN"})
    assert r.status_code == 200, f"Phone recon failed: {r.text}"
    pdata = r.json()
    assert pdata.get("status") == "success", "Phone recon not successful"
    assert "upi_ecosystem" in pdata, "Missing UPI ecosystem"
    assert "telecom_intel" in pdata, "Missing telecom intel"
    assert len(pdata.get("upi_ecosystem", [])) > 0, "UPI VPAs empty"
    print(f"✅ [2/8] /api/recon/phone: PASS (Valid: {pdata.get('valid')}, Carrier: {pdata.get('telecom_intel', {}).get('carrier')}, VPAs: {len(pdata.get('upi_ecosystem'))})")

    # 3. Sherlock Username Recon
    r = client.post("/api/recon/username", json={"username": "torvalds"})
    assert r.status_code == 200, f"Username recon failed: {r.text}"
    sdata = r.json()
    assert sdata.get("status") == "success", "Username scan not successful"
    assert sdata.get("total_found", 0) > 0, "Sherlock failed to find known user"
    print(f"✅ [3/8] /api/recon/username: PASS (Found on {sdata.get('total_found')} platforms)")

    # 4. Reddit User Intelligence
    r = client.post("/api/recon/reddit/user", json={"username": "spez"})
    assert r.status_code == 200, f"Reddit user recon failed: {r.text}"
    rdata = r.json()
    assert "dorks" in rdata or "profile" in rdata, "Reddit user response missing dorks or profile"
    print(f"✅ [4/8] /api/recon/reddit/user: PASS (Status: {rdata.get('status')}, Dorks: {len(rdata.get('dorks', []))})")

    # 5. Reddit Search & Dorks
    r = client.post("/api/recon/reddit/search", json={"query": "OSINT tools", "limit": 5})
    assert r.status_code == 200, f"Reddit search failed: {r.text}"
    rsdata = r.json()
    assert "dorks" in rsdata, "Reddit search missing dorks"
    print(f"✅ [5/8] /api/recon/reddit/search: PASS (Status: {rsdata.get('status')}, Dorks: {len(rsdata.get('dorks', []))})")

    # 6. Domain Recon
    r = client.post("/api/recon/domain", json={"domain": "google.com"})
    assert r.status_code == 200, f"Domain recon failed: {r.text}"
    ddata = r.json()
    assert ddata.get("status") == "success", "Domain recon failed"
    print(f"✅ [6/8] /api/recon/domain: PASS (A Records: {len(ddata.get('dns_records', {}).get('A', []))})")

    # 7. Email Intel
    r = client.post("/api/recon/email", json={"email": "security@rajlabs.in"})
    assert r.status_code == 200, f"Email recon failed: {r.text}"
    edata = r.json()
    assert edata.get("status") == "success", "Email recon failed"
    print(f"✅ [7/8] /api/recon/email: PASS (Domain: {edata.get('domain')}, MX Valid: {edata.get('domain_has_mx')})")

    # 8. Settings & Keystore Status
    r = client.get("/api/settings")
    assert r.status_code == 200, f"Settings failed: {r.text}"
    setdata = r.json()
    keys_list = [k.get("key") for k in setdata.get("keys", [])]
    assert "REDDIT_CLIENT_ID" in keys_list, "REDDIT_CLIENT_ID missing from keystore registry"
    assert "TELEGRAM_API_ID" in keys_list, "TELEGRAM_API_ID missing from keystore registry"
    print(f"✅ [8/8] /api/settings: PASS ({len(keys_list)} keys registered)")

    print("\n🎉 ALL 8 TESTS PASSED FULLY AND VERIFIED!")

if __name__ == "__main__":
    run_tests()
