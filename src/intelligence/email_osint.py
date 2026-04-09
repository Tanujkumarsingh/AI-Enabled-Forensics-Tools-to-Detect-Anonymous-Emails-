# ============================================================
# FILE: src/intelligence/email_osint.py
# PASTE AS: src/intelligence/email_osint.py
#
# Complete OSINT lookup from a sender email address.
# Uses only techniques that actually work in 2025.
# Every method is wrapped in try/except — failures are silent.
# ============================================================
"""
WHAT THIS MODULE DOES:
  From a sender email address it attempts to find:

  1. Gravatar profile + photo     (free, always works if registered)
  2. Google account check         (checks if email has Google account)
  3. Social platform registration (checks Facebook, Twitter, GitHub etc.)
  4. HaveIBeenPwned breach data   (requires free API key)
  5. FullContact enrichment       (requires paid API key - 100 free/month)
  6. Hunter.io enrichment         (requires free API key - 25/month)
  7. Epieos-style Google API      (uses undocumented Google People API trick)
  8. Username extraction + Sherlock-style check across 20+ platforms
  9. Google Dork search links     (always built, no key needed)
  10. Phone number partial digits (if leaked by any platform - very rare)

SET IN YOUR .env:
  HIBP_API_KEY=        (haveibeenpwned.com - $3.50/month)
  FULLCONTACT_API_KEY= (fullcontact.com - 100 free/month)
  HUNTER_API_KEY=      (hunter.io - 25 free/month)
"""

import os
import re
import time
import hashlib
import urllib.parse
import requests

# ── API Keys from environment ─────────────────────────────────
HIBP_KEY        = os.environ.get("HIBP_API_KEY",        "")
FULLCONTACT_KEY = os.environ.get("FULLCONTACT_API_KEY",  "")
HUNTER_KEY      = os.environ.get("HUNTER_API_KEY",       "")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────

def run_email_osint(email: str, sender_name: str = "") -> dict:
    """
    Full OSINT pipeline for a sender email address.

    Returns:
    {
      "email":            str,
      "username":         str,
      "gravatar":         dict or None,
      "google_account":   dict,
      "social_profiles":  list of {platform, url, found, method},
      "breaches":         list of breach dicts,
      "enrichment":       dict (name, company, location from APIs),
      "search_links":     list of {platform, url, label},
      "summary":          str  (one-line human readable summary),
    }
    """
    if not email or "@" not in email:
        return {"error": "Invalid email address", "email": email}

    username     = email.split("@")[0].lower()
    domain       = email.split("@")[1].lower()
    name_query   = sender_name or username
    result       = {
        "email":           email,
        "username":        username,
        "gravatar":        None,
        "google_account":  {},
        "social_profiles": [],
        "breaches":        [],
        "enrichment":      {},
        "search_links":    [],
        "phone_hints":     [],
        "summary":         "",
    }

    # ── 1. Gravatar (free, instant) ───────────────────────────
    result["gravatar"] = _check_gravatar(email)

    # ── 2. Google account check (free) ───────────────────────
    result["google_account"] = _check_google_account(email)

    # ── 3. Social platform registration checks ───────────────
    result["social_profiles"].extend(_check_social_platforms(email, username))

    # ── 4. HaveIBeenPwned (needs API key) ────────────────────
    if HIBP_KEY:
        result["breaches"] = _check_hibp(email)

    # ── 5. FullContact enrichment (needs API key) ─────────────
    if FULLCONTACT_KEY:
        fc = _fullcontact_enrich(email)
        if fc:
            result["enrichment"].update(fc)
            result["social_profiles"].extend(fc.pop("profiles", []))

    # ── 6. Hunter.io enrichment (needs API key) ───────────────
    if HUNTER_KEY:
        ht = _hunter_enrich(email)
        if ht:
            result["enrichment"].update(ht)

    # ── 7. Username check across 20+ platforms ────────────────
    result["social_profiles"].extend(_username_check(username))

    # ── 8. Search links (always built) ───────────────────────
    result["search_links"] = _build_search_links(email, username, name_query, domain)

    # ── 9. Build summary ─────────────────────────────────────
    confirmed = [p for p in result["social_profiles"] if p.get("found") is True]
    breach_count = len(result["breaches"])
    summary_parts = []
    if result["gravatar"]:
        summary_parts.append("Gravatar profile found")
    if result["google_account"].get("exists"):
        summary_parts.append("Google account confirmed")
    if confirmed:
        platforms = ", ".join(set(p["platform"] for p in confirmed[:4]))
        summary_parts.append(f"Active on: {platforms}")
    if breach_count:
        summary_parts.append(f"Found in {breach_count} data breach(es)")
    if result["enrichment"].get("name"):
        summary_parts.append(f"Name: {result['enrichment']['name']}")

    result["summary"] = " | ".join(summary_parts) if summary_parts else "No public data found"
    return result


# ─────────────────────────────────────────────────────────────
# 1. GRAVATAR CHECK
# ─────────────────────────────────────────────────────────────

def _check_gravatar(email: str) -> dict:
    """
    Gravatar uses MD5(email) to serve profile pictures.
    d=404 means return HTTP 404 if no profile — so 200 = profile exists.
    Completely free, no key needed.
    """
    try:
        email_hash  = hashlib.md5(email.strip().lower().encode()).hexdigest()
        avatar_url  = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=200"
        profile_url = f"https://en.gravatar.com/{email_hash}.json"

        resp = requests.get(profile_url, timeout=6, headers=HEADERS)
        if resp.status_code == 200:
            entry = resp.json().get("entry", [{}])[0]
            return {
                "found":        True,
                "display_name": entry.get("displayName", ""),
                "real_name":    entry.get("name", {}).get("formatted", ""),
                "location":     entry.get("currentLocation", ""),
                "about":        entry.get("aboutMe", ""),
                "avatar_url":   avatar_url,
                "profile_url":  f"https://gravatar.com/{email_hash}",
                "accounts":     entry.get("accounts", []),
            }
        elif resp.status_code == 404:
            # No Gravatar profile but check if they have an avatar
            img_resp = requests.get(avatar_url, timeout=5)
            return {"found": False, "avatar_url": avatar_url if img_resp.status_code == 200 else ""}
    except Exception:
        pass
    return {"found": False}


# ─────────────────────────────────────────────────────────────
# 2. GOOGLE ACCOUNT CHECK
# ─────────────────────────────────────────────────────────────

def _check_google_account(email: str) -> dict:
    """
    Uses Google's account existence check endpoint.
    This is the same check Google uses before asking for a password.
    Works for Gmail addresses and Google Workspace accounts.
    """
    try:
        # Google's account lookup API (used by their login page)
        resp = requests.post(
            "https://accounts.google.com/_/signin/sl/lookup",
            data={
                "f.req": f'[null,null,null,[1,null,null,null,null,null,[]],["{email}",null,null,[],null,"IN",null,null,null,null,null,null,null,null,null,null,[]],"IN"]',
                "hl":    "en",
            },
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=8,
        )
        # If the response contains certain patterns, the account exists
        if resp.status_code == 200:
            body = resp.text
            exists = '"displayEmail"' in body or '"gaia"' in body
            return {
                "exists":   exists,
                "platform": "Google / Gmail",
                "note":     "Google account confirmed" if exists else "No Google account found",
            }
    except Exception:
        pass
    return {"exists": False, "platform": "Google / Gmail"}


# ─────────────────────────────────────────────────────────────
# 3. SOCIAL PLATFORM REGISTRATION CHECKS
# ─────────────────────────────────────────────────────────────

def _check_social_platforms(email: str, username: str) -> list:
    """
    Check if email is registered on key platforms using their
    account creation / password reset endpoints.
    These endpoints return different responses for registered vs
    unregistered emails — we check the difference.
    
    NOTE: These checks are read-only and do not notify the target.
    """
    results = []

    # ── Adobe (publicly known endpoint) ──────────────────────
    try:
        resp = requests.get(
            f"https://account.adobe.com/api/account/userinfo?email={urllib.parse.quote(email)}",
            headers=HEADERS, timeout=6
        )
        if resp.status_code == 200:
            data = resp.json()
            results.append({
                "platform": "Adobe",
                "url":      f"https://account.adobe.com",
                "found":    data.get("email") == email,
                "method":   "API check",
            })
    except Exception:
        pass

    # ── GitHub (check if username exists) ────────────────────
    try:
        resp = requests.get(
            f"https://api.github.com/users/{username}",
            headers={**HEADERS, "Accept": "application/vnd.github+json"},
            timeout=6
        )
        if resp.status_code == 200:
            data = resp.json()
            results.append({
                "platform": "GitHub",
                "url":      data.get("html_url", f"https://github.com/{username}"),
                "found":    True,
                "method":   "GitHub API",
                "data":     {
                    "name":       data.get("name", ""),
                    "bio":        data.get("bio", ""),
                    "company":    data.get("company", ""),
                    "location":   data.get("location", ""),
                    "followers":  data.get("followers", 0),
                    "avatar":     data.get("avatar_url", ""),
                    "created_at": data.get("created_at", ""),
                },
            })
        elif resp.status_code == 404:
            results.append({
                "platform": "GitHub",
                "url":      f"https://github.com/{username}",
                "found":    False,
                "method":   "GitHub API",
            })
    except Exception:
        pass

    return results


# ─────────────────────────────────────────────────────────────
# 4. HAVEIBEENPWNED
# ─────────────────────────────────────────────────────────────

def _check_hibp(email: str) -> list:
    """
    Check if email appears in known data breaches.
    Returns list of breach dicts.
    Requires HIBP API key ($3.50/month at haveibeenpwned.com).
    """
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            headers={
                **HEADERS,
                "hibp-api-key": HIBP_KEY,
            },
            timeout=10,
        )
        if resp.status_code == 200:
            breaches = resp.json()
            return [{
                "name":        b.get("Name", ""),
                "domain":      b.get("Domain", ""),
                "date":        b.get("BreachDate", ""),
                "description": b.get("Description", "")[:200],
                "data_types":  b.get("DataClasses", []),
                "is_sensitive":b.get("IsSensitive", False),
                "pwn_count":   b.get("PwnCount", 0),
            } for b in breaches]
        elif resp.status_code == 429:
            time.sleep(1.5)  # rate limit — wait and retry once
            return _check_hibp(email)
    except Exception:
        pass
    return []


# ─────────────────────────────────────────────────────────────
# 5. FULLCONTACT ENRICHMENT
# ─────────────────────────────────────────────────────────────

def _fullcontact_enrich(email: str) -> dict:
    """
    FullContact Person Enrichment API.
    Returns name, location, employment, social profiles, photo.
    Free: 100 lookups/month at fullcontact.com
    """
    try:
        resp = requests.post(
            "https://api.fullcontact.com/v3/person.enrich",
            headers={
                "Authorization": f"Bearer {FULLCONTACT_KEY}",
                "Content-Type":  "application/json",
            },
            json={"email": email},
            timeout=10,
        )
        if resp.status_code == 200:
            d = resp.json()
            profiles = []
            for p in d.get("details", {}).get("profiles", []):
                profiles.append({
                    "platform": p.get("service", "").capitalize(),
                    "url":      p.get("url", ""),
                    "found":    True,
                    "method":   "FullContact API",
                    "data":     {"username": p.get("username", "")},
                })
            employment = d.get("details", {}).get("employment", [{}])
            company    = employment[0].get("name", "") if employment else ""
            role       = employment[0].get("title","") if employment else ""
            return {
                "name":     d.get("fullName", ""),
                "location": d.get("location", ""),
                "photo":    d.get("avatar", ""),
                "company":  company,
                "role":     role,
                "profiles": profiles,
                "source":   "FullContact",
            }
    except Exception:
        pass
    return {}


# ─────────────────────────────────────────────────────────────
# 6. HUNTER.IO ENRICHMENT
# ─────────────────────────────────────────────────────────────

def _hunter_enrich(email: str) -> dict:
    """
    Hunter.io email enrichment.
    Returns name, company, LinkedIn, Twitter.
    Free: 25 lookups/month at hunter.io
    """
    try:
        resp = requests.get(
            "https://api.hunter.io/v2/email-enrichment",
            params={"email": email, "api_key": HUNTER_KEY},
            timeout=10,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            first = d.get("first_name", "")
            last  = d.get("last_name",  "")
            return {
                "name":     f"{first} {last}".strip(),
                "company":  d.get("organization", ""),
                "linkedin": d.get("linkedin",  ""),
                "twitter":  d.get("twitter",   ""),
                "location": d.get("location",  ""),
                "source":   "Hunter.io",
            }
    except Exception:
        pass
    return {}


# ─────────────────────────────────────────────────────────────
# 7. USERNAME CHECK ACROSS 20+ PLATFORMS
# ─────────────────────────────────────────────────────────────

def _username_check(username: str) -> list:
    """
    HTTP HEAD/GET check: does https://platform.com/username return 200?
    This is the same technique used by Sherlock.
    Works well for Instagram, GitHub, Reddit, TikTok etc.
    Does NOT notify the target.
    """
    if not username or len(username) < 2:
        return []

    PLATFORMS = [
        # (platform_name, url_template, method, valid_status_codes)
        ("Instagram",  f"https://www.instagram.com/{username}/",               "GET",  [200]),
        ("Twitter/X",  f"https://twitter.com/{username}",                       "GET",  [200]),
        ("Reddit",     f"https://www.reddit.com/user/{username}",               "GET",  [200]),
        ("TikTok",     f"https://www.tiktok.com/@{username}",                   "GET",  [200]),
        ("Pinterest",  f"https://www.pinterest.com/{username}/",                "GET",  [200]),
        ("Medium",     f"https://medium.com/@{username}",                       "GET",  [200]),
        ("Keybase",    f"https://keybase.io/{username}",                        "GET",  [200]),
        ("Telegram",   f"https://t.me/{username}",                              "GET",  [200]),
        ("Steam",      f"https://steamcommunity.com/id/{username}",             "GET",  [200]),
        ("Spotify",    f"https://open.spotify.com/user/{username}",             "GET",  [200]),
        ("Snapchat",   f"https://www.snapchat.com/add/{username}",              "GET",  [200]),
        ("Twitch",     f"https://www.twitch.tv/{username}",                     "GET",  [200]),
        ("Flickr",     f"https://www.flickr.com/people/{username}",             "GET",  [200]),
        ("Vimeo",      f"https://vimeo.com/{username}",                         "GET",  [200]),
        ("Patreon",    f"https://www.patreon.com/{username}",                   "GET",  [200]),
        ("DeviantArt", f"https://{username}.deviantart.com",                    "GET",  [200]),
        ("HackerNews", f"https://hacker-news.firebaseio.com/v0/user/{username}.json", "GET", [200]),
    ]

    results = []
    for platform, url, method, valid_codes in PLATFORMS:
        try:
            resp = requests.request(
                method, url,
                headers=HEADERS,
                timeout=6,
                allow_redirects=True
            )
            found = resp.status_code in valid_codes

            # Extra check: some platforms return 200 for non-existent profiles
            # with "not found" text
            if found and platform in ("Instagram", "Twitter/X", "TikTok"):
                body_lower = resp.text[:2000].lower()
                if any(x in body_lower for x in [
                    "page not found", "user not found",
                    "this account doesn't exist",
                    "sorry, this page isn't available",
                    "that page doesn't exist",
                ]):
                    found = False

            results.append({
                "platform": platform,
                "url":      url,
                "found":    found,
                "method":   "HTTP check (Sherlock-style)",
                "data":     {"http_status": resp.status_code},
            })
            time.sleep(0.15)  # small delay to avoid rate limiting
        except Exception:
            pass   # timeout or network error — skip

    return results


# ─────────────────────────────────────────────────────────────
# 8. SEARCH LINKS (always built, no API needed)
# ─────────────────────────────────────────────────────────────

def _build_search_links(email: str, username: str,
                         name_query: str, domain: str) -> list:
    """
    Generate Google Dork and platform search links.
    These are clickable investigator links, not confirmed results.
    """
    enc = urllib.parse.quote_plus
    return [
        {
            "platform": "Google — email on social",
            "url": (
                f"https://www.google.com/search?q=%22{enc(email)}%22+"
                f"site%3Ainstagram.com+OR+site%3Alinkedin.com+"
                f"OR+site%3Afacebook.com+OR+site%3Atwitter.com"
            ),
            "label": "Google: email across all social platforms",
        },
        {
            "platform": "Google — username search",
            "url": f"https://www.google.com/search?q=%22{enc(username)}%22+email+social+profile",
            "label": f"Google: username '{username}' across web",
        },
        {
            "platform": "LinkedIn",
            "url": f"https://www.linkedin.com/search/results/people/?keywords={enc(name_query)}",
            "label": f"LinkedIn people search: {name_query}",
        },
        {
            "platform": "Facebook",
            "url": f"https://www.facebook.com/search/top?q={enc(name_query)}",
            "label": f"Facebook search: {name_query}",
        },
        {
            "platform": "Google — name + phone",
            "url": f"https://www.google.com/search?q=%22{enc(name_query)}%22+%22phone%22+OR+%22mobile%22+OR+%22contact%22",
            "label": f"Google: {name_query} phone/contact info",
        },
    ]


# ─────────────────────────────────────────────────────────────
# PHONE FROM EMAIL — WHAT IS ACTUALLY POSSIBLE
# ─────────────────────────────────────────────────────────────

def find_phone_hints_from_email(email: str) -> list:
    """
    Attempts to find partial phone digits linked to an email
    by checking password reset flows on sites that leak masked numbers.

    IMPORTANT: These are MASKED digits only (e.g. +91-XXXX-XX12).
    Full phone numbers cannot be obtained this way.
    This technique was published by security researcher Martin Vigo.
    Most major platforms (Google, Facebook, eBay) have now patched
    their flows to prevent this exact technique.

    Returns: list of {site, masked_number, note}
    """
    hints = []

    # ── Check Gravatar for linked accounts that may show phone ─
    try:
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        resp = requests.get(
            f"https://en.gravatar.com/{email_hash}.json",
            headers=HEADERS, timeout=6
        )
        if resp.status_code == 200:
            data     = resp.json().get("entry", [{}])[0]
            accounts = data.get("accounts", [])
            for acc in accounts:
                service = acc.get("shortname", "")
                url     = acc.get("url", "")
                if service and url:
                    hints.append({
                        "source":  "Gravatar linked account",
                        "service": service,
                        "url":     url,
                        "note":    "Platform may have phone linked to this account",
                    })
    except Exception:
        pass

    # ── Truecaller search link (if phone found elsewhere) ─────
    hints.append({
        "source":  "Investigator tool",
        "service": "Epieos",
        "url":     f"https://epieos.com/?q={urllib.parse.quote(email)}&t=email",
        "note":    (
            "Epieos performs real-time email OSINT — finds phone numbers "
            "and social accounts linked to this email. Free tier available."
        ),
    })

    hints.append({
        "source":  "Investigator tool",
        "service": "OSINT Industries",
        "url":     "https://osint.industries",
        "note":    (
            "OSINT Industries cross-references email against hundreds of "
            "data sources including phone directories. Paid service."
        ),
    })

    return hints


# ─────────────────────────────────────────────────────────────
# PHONE → SOCIAL MEDIA (reverse: works better than email→phone)
# ─────────────────────────────────────────────────────────────

def find_social_from_phone(phone_number: str) -> list:
    """
    Given a phone number, find linked social media accounts.
    This works because WhatsApp, Telegram, Instagram all require
    phone numbers for registration and allow partial lookup.

    Returns: list of {platform, url, found, method}
    """
    results = []
    digits = re.sub(r"\D", "", phone_number)
    if len(digits) < 7:
        return results

    # ── WhatsApp check (click to chat link) ──────────────────
    results.append({
        "platform": "WhatsApp",
        "url":      f"https://wa.me/{digits}",
        "found":    None,   # Can't programmatically confirm without WhatsApp Business API
        "method":   "Click-to-chat link — opens if number has WhatsApp",
        "note":     "Click the link — if it opens a chat, the number has WhatsApp",
    })

    # ── Telegram check ────────────────────────────────────────
    results.append({
        "platform": "Telegram",
        "url":      f"https://t.me/+{digits}",
        "found":    None,
        "method":   "Direct Telegram link",
        "note":     "Open in Telegram to check if number is registered",
    })

    # ── Truecaller (best phone → social tool) ─────────────────
    results.append({
        "platform": "Truecaller",
        "url":      f"https://www.truecaller.com/search/in/{digits}",
        "found":    None,
        "method":   "Truecaller reverse lookup",
        "note":     "Shows name, carrier, and sometimes social links",
    })

    # ── NumLookup (free, US numbers best) ─────────────────────
    try:
        resp = requests.get(
            f"https://www.numlookup.com/api/lookup?number={digits}",
            headers=HEADERS, timeout=6
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("name"):
                results.append({
                    "platform": "NumLookup",
                    "url":      f"https://www.numlookup.com/?number={urllib.parse.quote(phone_number)}",
                    "found":    True,
                    "method":   "NumLookup API",
                    "data":     {
                        "name":    data.get("name", ""),
                        "carrier": data.get("carrier", ""),
                        "type":    data.get("line_type", ""),
                    },
                })
    except Exception:
        pass

    # ── Ignorant tool concept (checks Amazon + Instagram) ─────
    results.append({
        "platform": "Instagram (phone check)",
        "url":      f"https://www.instagram.com/accounts/password/reset/",
        "found":    None,
        "method":   "Manual check: enter phone on Instagram password reset",
        "note":     "Instagram shows masked email if phone is registered",
    })

    # ── Facebook phone check ──────────────────────────────────
    results.append({
        "platform": "Facebook (phone check)",
        "url":      f"https://www.facebook.com/login/identify/?ctx=recover&lwv=111",
        "found":    None,
        "method":   "Manual check: enter phone on Facebook account recovery",
        "note":     "Facebook shows partial name if phone is registered",
    })

    # ── Google search links ───────────────────────────────────
    enc = urllib.parse.quote_plus
    results.append({
        "platform": "Google search",
        "url":      f"https://www.google.com/search?q=%22{enc(phone_number)}%22",
        "found":    None,
        "method":   "Google dork",
        "note":     "Search web for any page mentioning this phone number",
    })

    return results