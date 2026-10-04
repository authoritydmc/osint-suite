import os
import phonenumbers
import httpx
from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
from typing import Dict, Any, List, Optional

# Optional live-lookup keys (all no-op when unset — nothing is blocked).
# Free tiers: Numverify 250/mo, Abstract/Veriphone small monthly quota,
# IPQualityScore free trial. Set via env on the container.
NUMVERIFY_KEY = os.getenv("NUMVERIFY_KEY", "")
ABSTRACT_KEY = os.getenv("ABSTRACT_PHONE_KEY", "")
VERIPHONE_KEY = os.getenv("VERIPHONE_KEY", "")
IPQS_KEY = os.getenv("IPQS_KEY", "")
_HTTP_TIMEOUT = 6.0

def _live_lookups(client: httpx.AsyncClient, e164: str) -> Dict[str, Any]:
    """Optional key-based live validation (Numverify/Abstract/Veriphone/IPQS).

    Each provider is skipped silently when its key is unset or on any error,
    so the module works fully offline-capable with zero keys configured.
    """
    out: Dict[str, Any] = {}
    num = e164.replace("+", "")
    if NUMVERIFY_KEY:
        try:
            r = client.get("http://apilayer.net/api/validate",
                           params={"access_key": NUMVERIFY_KEY, "number": num,
                                   "format": 1}).json()
            if r.get("valid"):
                out["numverify"] = {"valid": True, "carrier": r.get("carrier"),
                    "line_type": r.get("line_type"), "location": r.get("location"),
                    "country": r.get("country_name")}
        except Exception:
            pass
    if ABSTRACT_KEY:
        try:
            r = client.get("https://phonevalidation.abstractapi.com/v1/",
                           params={"api_key": ABSTRACT_KEY, "phone": e164}).json()
            if r.get("valid") is not None:
                out["abstract"] = {"valid": r.get("valid"), "carrier": (r.get("carrier") or {}).get("name"),
                    "line_type": r.get("type"), "region": r.get("region")}
        except Exception:
            pass
    if VERIPHONE_KEY:
        try:
            r = client.get("https://api.veriphone.io/v2/verify",
                           params={"phone": e164, "key": VERIPHONE_KEY}).json()
            if r.get("status") == "success":
                out["veriphone"] = {"valid": r.get("phone_valid"),
                    "carrier": r.get("carrier"), "line_type": r.get("phone_type"),
                    "region": r.get("phone_region")}
        except Exception:
            pass
    if IPQS_KEY:
        try:
            r = client.get(f"https://www.ipqualityscore.com/api/json/phone/{IPQS_KEY}/{num}").json()
            if r.get("success"):
                out["ipqs"] = {"valid": r.get("valid"), "recent_abuse": r.get("recent_abuse"),
                    "voip": r.get("VOIP"), "risk_score": r.get("risk_score")}
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
        
        # Phone types mapping
        type_mapping = {
            PhoneNumberType.MOBILE: "Mobile",
            PhoneNumberType.FIXED_LINE: "Fixed Line (Landline)",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
            PhoneNumberType.TOLL_FREE: "Toll-Free",
            PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            PhoneNumberType.SHARED_COST: "Shared Cost",
            PhoneNumberType.VOIP: "VoIP",
            PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
            PhoneNumberType.PAGER: "Pager",
            PhoneNumberType.UAN: "Universal Access Number (UAN)",
            PhoneNumberType.VOICEMAIL: "Voicemail",
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
        
        # Heuristic Risk & Spam indicator
        risk_score = "Low"
        risk_reasons: List[str] = []
        
        if not is_valid:
            risk_score = "High"
            risk_reasons.append("Invalid phone number format")
        elif ntype == PhoneNumberType.VOIP:
            risk_score = "Medium"
            risk_reasons.append("Virtual / VoIP number - common in disposable SMS services")
        elif ntype == PhoneNumberType.PREMIUM_RATE:
            risk_score = "High"
            risk_reasons.append("Premium rate number - potential toll fraud")
            
        # Regional telecom circle detection (India)
        telecom_circle = geo_location if geo_location else "Unknown Circle"

        # Live key-based lookups (no-op without keys) + exposure score
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as _client:
            live = _live_lookups(_client, formatted_e164)

        exposure = 0
        if is_valid:
            exposure += 10
        if ntype == PhoneNumberType.MOBILE:
            exposure += 15  # mobile = WhatsApp/Telegram/UPI-able, highly exposed
        if live:
            exposure += 20  # resolvable in live validation DBs
        for prov in ("numverify", "abstract", "veriphone"):
            if live.get(prov, {}).get("valid"):
                exposure += 5
        if live.get("ipqs", {}).get("recent_abuse"):
            risk_score = "High"
            risk_reasons.append("IPQualityScore flags recent abuse on this number")
            exposure += 15
        exposure = min(exposure, 100)

        return {
            "status": "success",
            "valid": is_valid,
            "possible": is_possible,
            "exposure_score": exposure,
            "number_details": {
                "e164": formatted_e164,
                "international": formatted_intl,
                "national": formatted_nat,
                "rfc3966": formatted_rfc3966,
                "country_code": parsed.country_code,
                "national_number": str(parsed.national_number),
            },
            "telecom_intel": {
                "carrier": carrier_name if carrier_name else "Unknown Carrier / Ported",
                "line_type": type_str,
                "location": geo_location if geo_location else "Unknown Location",
                "telecom_circle": telecom_circle,
                "timezones": tz_list if tz_list else ["Unknown"],
            },
            "reputation_risk": {
                "risk_level": risk_score,
                "flags": risk_reasons,
                "is_disposable_risk": (ntype == PhoneNumberType.VOIP)
            },
            "live_lookups": live if live else {"note": "no API keys configured — set NUMVERIFY_KEY / ABSTRACT_PHONE_KEY / VERIPHONE_KEY / IPQS_KEY for live validation"},
            "external_lookups": [
                {"name": "Truecaller Web", "url": f"https://www.truecaller.com/search/in/{parsed.national_number}"},
                {"name": "Sync.me Directory", "url": f"https://sync.me/search/?number={formatted_e164}"},
                {"name": "Tellows Spam Score", "url": f"https://www.tellows.in/num/{digits}"},
                {"name": "ShouldIAnswer Rating", "url": f"https://www.shouldianswer.com/phone-number/{digits}"},
                {"name": "Whoscall Lookup", "url": f"https://whoscall.com/en-IN/{digits}"},
                {"name": "Eyecon Directory", "url": f"https://eyecon-app.com/?number={formatted_e164}"},
                {"name": "WhatsApp Direct", "url": f"https://wa.me/{digits}"},
                {"name": "Telegram Link", "url": f"https://t.me/+{digits}"},
                {"name": "Facebook Phone Search", "url": f"https://www.facebook.com/search/top/?q={digits}"},
                {"name": "Google Dork", "url": f"https://www.google.com/search?q=\"{formatted_intl}\"+OR+\"{formatted_nat}\""}
            ]
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "raw_input": raw_phone
        }
