import phonenumbers
from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
from typing import Dict, Any, List

def analyze_phone_number(raw_phone: str, default_region: str = "IN") -> Dict[str, Any]:
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

        return {
            "status": "success",
            "valid": is_valid,
            "possible": is_possible,
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
            "external_lookups": [
                {"name": "Truecaller Web", "url": f"https://www.truecaller.com/search/in/{parsed.national_number}"},
                {"name": "Sync.me Directory", "url": f"https://sync.me/search/?number={formatted_e164}"},
                {"name": "WhatsApp Direct", "url": f"https://wa.me/{formatted_e164.replace('+', '')}"},
                {"name": "Telegram Link", "url": f"https://t.me/+{formatted_e164.replace('+', '')}"},
                {"name": "Google Dork", "url": f"https://www.google.com/search?q=\"{formatted_intl}\"+OR+\"{formatted_nat}\""}
            ]
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "raw_input": raw_phone
        }
