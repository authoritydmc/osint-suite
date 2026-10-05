"""
app/core/phone_recon.py
=======================
Advanced Multi-Vector Phone Reconnaissance, NUMINT, Telecom HLR Matrix,
UPI Payment Ecosystem Pivots & Risk Assessment Engine.
"""

import os
import phonenumbers
import httpx
from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
from typing import Dict, Any, List, Optional
import urllib.parse

NUMVERIFY_KEY = os.getenv("NUMVERIFY_KEY", "")
ABSTRACT_KEY = os.getenv("ABSTRACT_PHONE_KEY", "")
VERIPHONE_KEY = os.getenv("VERIPHONE_KEY", "")
IPQS_KEY = os.getenv("IPQS_KEY", "")
_HTTP_TIMEOUT = 6.0

# India Telecom Circles & Region Matrix
INDIA_CIRCLES = {
    "AP": {"name": "Andhra Pradesh & Telangana", "code": "AP", "capital": "Hyderabad"},
    "AS": {"name": "Assam", "code": "AS", "capital": "Guwahati"},
    "BH": {"name": "Bihar & Jharkhand", "code": "BH", "capital": "Patna"},
    "CH": {"name": "Chennai", "code": "CH", "capital": "Chennai"},
    "DL": {"name": "Delhi & NCR", "code": "DL", "capital": "New Delhi"},
    "GJ": {"name": "Gujarat & Daman/Diu", "code": "GJ", "capital": "Ahmedabad"},
    "HP": {"name": "Himachal Pradesh", "code": "HP", "capital": "Shimla"},
    "HR": {"name": "Haryana", "code": "HR", "capital": "Ambala"},
    "JK": {"name": "Jammu & Kashmir", "code": "JK", "capital": "Srinagar / Jammu"},
    "KL": {"name": "Kerala & Lakshadweep", "code": "KL", "capital": "Kochi / Trivandrum"},
    "KA": {"name": "Karnataka", "code": "KA", "capital": "Bengaluru"},
    "KO": {"name": "Kolkata", "code": "KO", "capital": "Kolkata"},
    "MH": {"name": "Maharashtra & Goa", "code": "MH", "capital": "Pune"},
    "MP": {"name": "Madhya Pradesh & Chhattisgarh", "code": "MP", "capital": "Bhopal"},
    "MU": {"name": "Mumbai", "code": "MU", "capital": "Mumbai"},
    "NE": {"name": "North East (Arunachal, Manipur, Meghalaya, Mizoram, Nagaland, Tripura)", "code": "NE", "capital": "Shillong"},
    "OR": {"name": "Odisha", "code": "OR", "capital": "Bhubaneswar"},
    "PB": {"name": "Punjab", "code": "PB", "capital": "Chandigarh"},
    "RJ": {"name": "Rajasthan", "code": "RJ", "capital": "Jaipur"},
    "TN": {"name": "Tamil Nadu", "code": "TN", "capital": "Coimbatore / Madurai"},
    "UPE": {"name": "Uttar Pradesh (East)", "code": "UPE", "capital": "Lucknow"},
    "UPW": {"name": "Uttar Pradesh (West) & Uttarakhand", "code": "UPW", "capital": "Meerut / Dehradun"},
    "WB": {"name": "West Bengal & Sikkim", "code": "WB", "capital": "Siliguri"}
}

# Standard MCC / MNC Reference for Major Providers
MCC_MNC_TABLE = {
    "404": "India (DoT/TRAI)",
    "405": "India (DoT/TRAI)",
    "310": "United States",
    "311": "United States",
    "234": "United Kingdom",
    "424": "United Arab Emirates",
    "525": "Singapore",
    "505": "Australia",
    "262": "Germany",
    "302": "Canada"
}

def _live_lookups(client: httpx.AsyncClient, e164: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    num = e164.replace("+", "")
    if NUMVERIFY_KEY:
        try:
            r = client.get("http://apilayer.net/api/validate",
                           params={"access_key": NUMVERIFY_KEY, "number": num, "format": 1}).json()
            if r.get("valid"):
                out["numverify"] = {
                    "valid": True,
                    "carrier": r.get("carrier"),
                    "line_type": r.get("line_type"),
                    "location": r.get("location"),
                    "country": r.get("country_name")
                }
        except Exception:
            pass
    if ABSTRACT_KEY:
        try:
            r = client.get("https://phonevalidation.abstractapi.com/v1/",
                           params={"api_key": ABSTRACT_KEY, "phone": e164}).json()
            if r.get("valid") is not None:
                out["abstract"] = {
                    "valid": r.get("valid"),
                    "carrier": (r.get("carrier") or {}).get("name"),
                    "line_type": r.get("type"),
                    "region": r.get("region")
                }
        except Exception:
            pass
    if VERIPHONE_KEY:
        try:
            r = client.get("https://api.veriphone.io/v2/verify",
                           params={"phone": e164, "key": VERIPHONE_KEY}).json()
            if r.get("status") == "success":
                out["veriphone"] = {
                    "valid": r.get("phone_valid"),
                    "carrier": r.get("carrier"),
                    "line_type": r.get("phone_type"),
                    "region": r.get("phone_region")
                }
        except Exception:
            pass
    if IPQS_KEY:
        try:
            r = client.get(f"https://www.ipqualityscore.com/api/json/phone/{IPQS_KEY}/{num}").json()
            if r.get("success"):
                out["ipqs"] = {
                    "valid": r.get("valid"),
                    "recent_abuse": r.get("recent_abuse"),
                    "voip": r.get("VOIP"),
                    "risk_score": r.get("risk_score")
                }
        except Exception:
            pass
    return out


async def analyze_phone_number(raw_phone: str, default_region: str = "IN") -> Dict[str, Any]:
    try:
        clean_input = raw_phone.strip()
        if not clean_input.startswith("+") and default_region:
            parsed = phonenumbers.parse(clean_input, default_region)
        else:
            parsed = phonenumbers.parse(clean_input, None)
        
        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)
        
        type_mapping = {
            PhoneNumberType.MOBILE: "Mobile / Cellular",
            PhoneNumberType.FIXED_LINE: "Fixed Line (Landline)",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
            PhoneNumberType.TOLL_FREE: "Toll-Free (Toll Free 1800/800)",
            PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            PhoneNumberType.SHARED_COST: "Shared Cost",
            PhoneNumberType.VOIP: "VoIP (Virtual / Cloud PBX)",
            PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
            PhoneNumberType.PAGER: "Pager",
            PhoneNumberType.UAN: "Universal Access Number (UAN)",
            PhoneNumberType.VOICEMAIL: "Voicemail Access",
            PhoneNumberType.UNKNOWN: "Unknown"
        }
        
        ntype = phonenumbers.number_type(parsed)
        type_str = type_mapping.get(ntype, "Unknown")
        
        geo_location = geocoder.description_for_number(parsed, "en")
        carrier_name = carrier.name_for_number(parsed, "en")
        tz_list = list(timezone.time_zones_for_number(parsed))
        
        formatted_intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        formatted_nat = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        formatted_e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        formatted_rfc3966 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966)
        digits = formatted_e164.replace("+", "")
        nat_number = str(parsed.national_number)
        
        # Telecom circle & HLR identification
        telecom_circle = geo_location if geo_location else "National / All Circles"
        circle_meta = None
        for code, cdata in INDIA_CIRCLES.items():
            if cdata["name"].lower() in telecom_circle.lower() or cdata["capital"].lower() in telecom_circle.lower():
                circle_meta = cdata
                break

        # Risk & Threat calculation
        risk_level = "Low"
        risk_score_num = 15
        risk_flags: List[str] = []
        
        if not is_valid:
            risk_level = "Critical"
            risk_score_num = 95
            risk_flags.append("Invalid or unallocated number format")
        elif ntype == PhoneNumberType.VOIP:
            risk_level = "Elevated"
            risk_score_num = 65
            risk_flags.append("Virtual / VoIP number - common in disposable SMS and spoofing")
        elif ntype == PhoneNumberType.PREMIUM_RATE:
            risk_level = "High"
            risk_score_num = 85
            risk_flags.append("Premium rate number - potential toll/tariff fraud")
            
        if ntype == PhoneNumberType.MOBILE:
            risk_flags.append("Active mobile range - SMS, WhatsApp & UPI payment capable")

        # Live external API lookups
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as _client:
            live = _live_lookups(_client, formatted_e164)

        # Exposure score calculation (0 - 100)
        exposure = 20
        if is_valid:
            exposure += 15
        if ntype == PhoneNumberType.MOBILE:
            exposure += 25  # High social & financial exposure
        if live:
            exposure += 15
        if live.get("ipqs", {}).get("recent_abuse"):
            risk_level = "Critical"
            risk_score_num = 90
            risk_flags.append("IPQualityScore flags active fraud/abuse on this number")
            exposure += 20
        exposure = min(exposure, 100)

        # UPI Virtual Payment Addresses (India Specific)
        upi_vpas = []
        if parsed.country_code == 91:
            upi_vpas = [
                {"provider": "PhonePe (Primary)", "vpa": f"{nat_number}@ybl"},
                {"provider": "PhonePe (ICICI)", "vpa": f"{nat_number}@ibl"},
                {"provider": "PhonePe (Axis)", "vpa": f"{nat_number}@axl"},
                {"provider": "Google Pay (Axis)", "vpa": f"{nat_number}@okaxis"},
                {"provider": "Google Pay (HDFC)", "vpa": f"{nat_number}@okhdfcbank"},
                {"provider": "Google Pay (SBI)", "vpa": f"{nat_number}@oksbi"},
                {"provider": "Google Pay (ICICI)", "vpa": f"{nat_number}@okicici"},
                {"provider": "Paytm Payments Bank", "vpa": f"{nat_number}@paytm"},
                {"provider": "BHIM UPI", "vpa": f"{nat_number}@upi"},
                {"provider": "Amazon Pay", "vpa": f"{nat_number}@apl"}
            ]

        # Categorized Recon & Dork Matrix
        q_intl = urllib.parse.quote(f'"{formatted_intl}"')
        q_nat = urllib.parse.quote(f'"{formatted_nat}"')
        q_e164 = urllib.parse.quote(f'"{formatted_e164}"')
        q_digits = urllib.parse.quote(f'"{digits}"')
        q_combined = f'{q_e164}+OR+{q_intl}+OR+{q_nat}'

        recon_categories = {
            "messaging": [
                {"name": "WhatsApp Direct Chat", "url": f"https://wa.me/{digits}", "icon": "fa-brands fa-whatsapp", "badge": "Direct Chat"},
                {"name": "Telegram Account Link", "url": f"https://t.me/+{digits}", "icon": "fa-brands fa-telegram", "badge": "Channel/User"},
                {"name": "Viber Direct Call/Chat", "url": f"viber://chat?number=%2B{digits}", "icon": "fa-brands fa-viber", "badge": "Viber App"},
                {"name": "Signal Link Guide", "url": f"https://signal.me/#p/+{digits}", "icon": "fa-solid fa-comment-dots", "badge": "Signal E2EE"}
            ],
            "directories": [
                {"name": "Truecaller Web Directory", "url": f"https://www.truecaller.com/search/in/{nat_number}", "icon": "fa-solid fa-address-book", "badge": "Name/Spam Score"},
                {"name": "Sync.me Community Directory", "url": f"https://sync.me/search/?number={formatted_e164}", "icon": "fa-solid fa-users", "badge": "Social Match"},
                {"name": "Eyecon Directory Lookup", "url": f"https://eyecon-app.com/?number={formatted_e164}", "icon": "fa-solid fa-id-card", "badge": "Photo Match"},
                {"name": "Tellows Community Rating", "url": f"https://www.tellows.in/num/{digits}", "icon": "fa-solid fa-shield-virus", "badge": "Caller Type"},
                {"name": "ShouldIAnswer Spam Check", "url": f"https://www.shouldianswer.com/phone-number/{digits}", "icon": "fa-solid fa-user-shield", "badge": "User Reviews"},
                {"name": "Whoscall Global Directory", "url": f"https://whoscall.com/en-IN/{digits}", "icon": "fa-solid fa-phone-volume", "badge": "Telemarketer"},
                {"name": "CallApp Caller ID", "url": f"https://callapp.com/lookup/{formatted_e164}", "icon": "fa-solid fa-phone", "badge": "Caller Intel"},
                {"name": "EmobileTracker (India Trace)", "url": f"https://www.emobiletracker.com/free-trace-tracker.php?phone={nat_number}", "icon": "fa-solid fa-tower-broadcast", "badge": "Circle & HLR"}
            ],
            "social": [
                {"name": "Facebook Account Search", "url": f"https://www.facebook.com/search/top/?q={digits}", "icon": "fa-brands fa-facebook", "badge": "Profile Search"},
                {"name": "LinkedIn Phone Search", "url": f"https://www.google.com/search?q=site:linkedin.com/in/+({q_e164}+OR+{q_nat})", "icon": "fa-brands fa-linkedin", "badge": "Professional"},
                {"name": "Instagram Profile Mentions", "url": f"https://www.google.com/search?q=site:instagram.com+({q_e164}+OR+{q_nat})", "icon": "fa-brands fa-instagram", "badge": "Bio/Posts"},
                {"name": "Twitter / X Search", "url": f"https://twitter.com/search?q=%22{digits}%22&f=live", "icon": "fa-brands fa-twitter", "badge": "Live Tweets"},
                {"name": "VKontakte Profile Search", "url": f"https://vk.com/search?c%5Bsection%5D=people&c%5Bq%5D=%2B{digits}", "icon": "fa-brands fa-vk", "badge": "Eastern Europe"}
            ],
            "dorks": [
                {"name": "All-in-One Digital Footprint", "url": f"https://www.google.com/search?q={q_combined}", "icon": "fa-brands fa-google", "badge": "General Recon"},
                {"name": "Pastebin & Secret Leaks", "url": f"https://www.google.com/search?q={q_e164}+(site:pastebin.com+OR+site:ghostbin.com+OR+site:justpaste.it+OR+site:throwbin.io)", "icon": "fa-solid fa-paste", "badge": "Public Pastes"},
                {"name": "Document & PDF/Excel Leaks", "url": f"https://www.google.com/search?q={q_e164}+(filetype:pdf+OR+filetype:xlsx+OR+filetype:csv+OR+filetype:docx+OR+filetype:txt)", "icon": "fa-solid fa-file-pdf", "badge": "Files & Tables"},
                {"name": "Classifieds & OLX/Quikr Ads", "url": f"https://www.google.com/search?q={q_e164}+(site:olx.in+OR+site:quikr.com+OR+site:craigslist.org+OR+site:indiamart.com)", "icon": "fa-solid fa-store", "badge": "Marketplaces"},
                {"name": "Resumes & CV Listings", "url": f"https://www.google.com/search?q={q_e164}+(resume+OR+cv+OR+\"curriculum+vitae\"+OR+\"contact+me\")", "icon": "fa-solid fa-file-lines", "badge": "Job Portals"},
                {"name": "Telegram Channels & Groups", "url": f"https://www.google.com/search?q=site:t.me+({q_e164}+OR+{q_nat})", "icon": "fa-brands fa-telegram", "badge": "Channel History"}
            ],
            "telecom_tools": [
                {"name": "FreeCarrierLookup", "url": "https://freecarrierlookup.com/", "icon": "fa-solid fa-tower-cell", "badge": "Carrier & LRN"},
                {"name": "TextMagic Carrier Check", "url": "https://www.textmagic.com/free-tools/carrier-lookup/", "icon": "fa-solid fa-signal", "badge": "Live Routing"},
                {"name": "HLR Lookup Live Portal", "url": "https://www.hlrlookup.com/", "icon": "fa-solid fa-network-wired", "badge": "SS7 / HLR Query"}
            ]
        }

        # Flattened legacy list for backward compatibility
        flat_lookups = []
        for cat_items in recon_categories.values():
            for it in cat_items:
                flat_lookups.append({"name": it["name"], "url": it["url"]})

        return {
            "status": "success",
            "valid": is_valid,
            "possible": is_possible,
            "exposure_score": exposure,
            "fraud_risk_score": risk_score_num,
            "number_details": {
                "e164": formatted_e164,
                "international": formatted_intl,
                "national": formatted_nat,
                "rfc3966": formatted_rfc3966,
                "country_code": parsed.country_code,
                "national_number": nat_number,
                "raw_digits": digits,
                "country_iso": geocoder.country_name_for_number(parsed, "en") or "Global",
            },
            "telecom_intel": {
                "carrier": carrier_name if carrier_name else "Unknown Carrier / Ported",
                "line_type": type_str,
                "location": geo_location if geo_location else "National Range",
                "telecom_circle": telecom_circle,
                "circle_info": circle_meta,
                "timezones": tz_list if tz_list else ["Asia/Kolkata"],
                "mcc_summary": MCC_MNC_TABLE.get(str(parsed.country_code), "International ITU Region")
            },
            "reputation_risk": {
                "risk_level": risk_level,
                "risk_score_numeric": risk_score_num,
                "flags": risk_flags,
                "is_disposable_risk": (ntype == PhoneNumberType.VOIP),
                "is_premium_rate": (ntype == PhoneNumberType.PREMIUM_RATE)
            },
            "upi_ecosystem": upi_vpas,
            "recon_categories": recon_categories,
            "external_lookups": flat_lookups,
            "live_lookups": live if live else {"note": "No 3rd-party API keys configured — set NUMVERIFY_KEY / ABSTRACT_PHONE_KEY / VERIPHONE_KEY / IPQS_KEY for live data"}
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "raw_input": raw_phone
        }
