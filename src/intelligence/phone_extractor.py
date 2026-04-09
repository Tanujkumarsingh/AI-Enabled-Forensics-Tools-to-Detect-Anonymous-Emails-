# ============================================================
# FILE: src/intelligence/phone_extractor.py
# PASTE AS: src/intelligence/phone_extractor.py
# ============================================================
"""
Phone number extraction AND reverse lookup.

Does two things:
  1. Extracts phone numbers written inside the email body (regex)
  2. If a phone number is found, looks it up using:
       - NumVerify API (carrier, line type, country) — free tier: 100/month
       - PhoneInfoga-style Google search links (free, no key needed)

Set in your .env:
  NUMVERIFY_API_KEY=your_key    (get at numverify.com — 100 free/month)
"""

import re
import os
import urllib.parse
import requests

NUMVERIFY_KEY = os.environ.get("NUMVERIFY_API_KEY", "")

# ─────────────────────────────────────────────────────────────
# PHONE NUMBER PATTERNS
# ─────────────────────────────────────────────────────────────

PHONE_PATTERNS = [
    r"\+?1?\s?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}",          # US/Canada
    r"\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{3,4}[\s.\-]?\d{4}",  # International
    r"\+91[\s.\-]?\d{10}",                                        # India
    r"\+44[\s.\-]?\d{10}",                                        # UK
    r"\+61[\s.\-]?\d{9}",                                         # Australia
    r"\+49[\s.\-]?\d{10,11}",                                     # Germany
    r"\+33[\s.\-]?\d{9}",                                         # France
    r"\b\d{10}\b",                                                 # 10-digit bare
    r"\b\d{3}[\s.\-]\d{3}[\s.\-]\d{4}\b",                        # 555-555-5555
    r"\b\d{5}[\s.\-]\d{5}\b",                                     # India local
]


# ─────────────────────────────────────────────────────────────
# EXTRACT FROM EMAIL BODY
# ─────────────────────────────────────────────────────────────

def extract_phones(text: str) -> list:
    """
    Extract all phone numbers written inside the email body.
    Returns a deduplicated list of phone number strings.
    """
    if not text:
        return []
    found = set()
    for pattern in PHONE_PATTERNS:
        for match in re.findall(pattern, text):
            cleaned = re.sub(r"\s+", " ", match.strip())
            digits  = re.sub(r"\D", "", cleaned)
            if 7 <= len(digits) <= 15:
                found.add(cleaned)
    return list(found)


# ─────────────────────────────────────────────────────────────
# REVERSE LOOKUP FOR EXTRACTED PHONES
# ─────────────────────────────────────────────────────────────

def lookup_phone(phone_number: str) -> dict:
    """
    Look up a phone number to get carrier, line type, country,
    and social media search links.

    Returns:
    {
      "number":      cleaned number,
      "valid":       bool,
      "country":     str,
      "carrier":     str,
      "line_type":   "mobile" | "landline" | "voip" | "unknown",
      "country_code": str,
      "search_links": list of {platform, url}
    }
    """
    result = {
        "number":       phone_number,
        "valid":        False,
        "country":      "",
        "carrier":      "",
        "line_type":    "unknown",
        "country_code": "",
        "search_links": [],
    }

    # Clean to digits only for API
    digits = re.sub(r"\D", "", phone_number)
    if not digits or len(digits) < 7:
        return result

    # Ensure E.164 format for API
    if not phone_number.startswith("+"):
        if len(digits) == 10:
            phone_number = "+1" + digits   # assume US if 10 digits
        else:
            phone_number = "+" + digits

    # ── NumVerify API ─────────────────────────────────────────
    if NUMVERIFY_KEY:
        try:
            resp = requests.get(
                "http://apilayer.net/api/validate",
                params={
                    "access_key": NUMVERIFY_KEY,
                    "number":     phone_number.lstrip("+"),
                    "country_code": "",
                    "format":     1,
                },
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    result["valid"]        = True
                    result["country"]      = data.get("country_name", "")
                    result["country_code"] = data.get("country_code", "")
                    result["carrier"]      = data.get("carrier", "")
                    result["line_type"]    = data.get("line_type", "unknown")
        except Exception:
            pass

    # ── Fallback: country code → country name ─────────────────
    if not result["country"] and phone_number.startswith("+"):
        result["country"] = _country_from_code(phone_number)
        result["valid"]   = True

    # ── Search links (always built, no API needed) ─────────────
    result["search_links"] = _phone_search_links(phone_number, digits)

    return result


def lookup_all_phones(text: str) -> list:
    """
    Extract all phones from body text, then look up each one.
    Returns list of lookup result dicts.
    """
    numbers = extract_phones(text)
    return [lookup_phone(num) for num in numbers]


# ─────────────────────────────────────────────────────────────
# PHONE SEARCH LINKS (no API — like PhoneInfoga)
# ─────────────────────────────────────────────────────────────

def _phone_search_links(phone: str, digits: str) -> list:
    """
    Generate OSINT search links for a phone number.
    These are the same links PhoneInfoga generates.
    """
    enc = urllib.parse.quote_plus
    return [
        {
            "platform": "Google",
            "url": f"https://www.google.com/search?q=%22{enc(phone)}%22",
            "label": f"Google search: {phone}",
        },
        {
            "platform": "Google Social",
            "url": f"https://www.google.com/search?q=%22{enc(phone)}%22+site%3Afacebook.com+OR+site%3Ainstagram.com+OR+site%3Alinkedin.com",
            "label": f"Social media search: {phone}",
        },
        {
            "platform": "Truecaller",
            "url": f"https://www.truecaller.com/search/in/{digits}",
            "label": f"Truecaller lookup: {phone}",
        },
        {
            "platform": "NumLookup",
            "url": f"https://www.numlookup.com/?number={enc(phone)}",
            "label": f"NumLookup reverse: {phone}",
        },
        {
            "platform": "SpyDialer",
            "url": f"https://www.spydialer.com/default.aspx?phone={digits}",
            "label": f"SpyDialer lookup: {phone}",
        },
        {
            "platform": "WhitePages",
            "url": f"https://www.whitepages.com/phone/{digits}",
            "label": f"WhitePages reverse: {phone}",
        },
    ]


# ─────────────────────────────────────────────────────────────
# COUNTRY CODE MAP
# ─────────────────────────────────────────────────────────────

COUNTRY_CODES = {
    "+1":  "United States / Canada",
    "+7":  "Russia / Kazakhstan",
    "+20": "Egypt",
    "+27": "South Africa",
    "+33": "France",
    "+34": "Spain",
    "+39": "Italy",
    "+44": "United Kingdom",
    "+49": "Germany",
    "+52": "Mexico",
    "+55": "Brazil",
    "+61": "Australia",
    "+62": "Indonesia",
    "+63": "Philippines",
    "+64": "New Zealand",
    "+65": "Singapore",
    "+66": "Thailand",
    "+81": "Japan",
    "+82": "South Korea",
    "+86": "China",
    "+90": "Turkey",
    "+91": "India",
    "+92": "Pakistan",
    "+94": "Sri Lanka",
    "+95": "Myanmar",
    "+98": "Iran",
}

def _country_from_code(phone: str) -> str:
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if phone.startswith(code):
            return country
    return ""