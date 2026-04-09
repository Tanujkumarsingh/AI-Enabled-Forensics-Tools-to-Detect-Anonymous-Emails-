# ============================================================
# FILE: src/intelligence/social_lookup.py
# PASTE AS: src/intelligence/social_lookup.py
# ============================================================
"""
Real social media and identity lookup from sender email address.

Supports:
  1. FullContact API  — finds real linked social profiles (100 free/month)
  2. HaveIBeenPwned   — checks if email appears in data breaches (free)
  3. Gravatar         — finds profile picture linked to email (free)
  4. Hunter.io        — email enrichment: name, company, social (paid/free tier)
  5. Sherlock         — username search across 400+ platforms (free, local)
  6. Search URL links — always generated as fallback (free, no API needed)

Set these in your .env file:
  FULLCONTACT_API_KEY=your_key      (get at fullcontact.com — 100 free/month)
  HIBP_API_KEY=your_key             (get at haveibeenpwned.com — $3.50/month)
  HUNTER_API_KEY=your_key           (get at hunter.io — 25 free/month)
"""

import os
import re
import hashlib
import urllib.parse
import requests

FULLCONTACT_KEY = os.environ.get("FULLCONTACT_API_KEY", "")
HIBP_KEY        = os.environ.get("HIBP_API_KEY", "")
HUNTER_KEY      = os.environ.get("HUNTER_API_KEY", "")


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────

def find_social_links(sender_email: str, sender_name: str = "") -> list:
    """
    Full social media and identity lookup for a sender email address.
    Returns list of dicts:
      { platform, url, label, type, found, data }
    
    type values:
      "real_profile"  — actual confirmed profile URL from API
      "search_link"   — search page URL (not confirmed, needs manual check)
      "breach"        — data breach record
      "gravatar"      — profile picture
      "enrichment"    — name/company/social from enrichment API
    """
    if not sender_email:
        return []

    results = []
    username   = sender_email.split("@")[0] if "@" in sender_email else sender_email
    name_query = sender_name or username

    # ── 1. FullContact API (real profile lookup) ──────────────
    if FULLCONTACT_KEY:
        fc_results = _fullcontact_lookup(sender_email)
        results.extend(fc_results)

    # ── 2. Hunter.io email enrichment ────────────────────────
    if HUNTER_KEY:
        hunter_results = _hunter_lookup(sender_email)
        results.extend(hunter_results)

    # ── 3. HaveIBeenPwned breach check ───────────────────────
    if HIBP_KEY:
        breach_results = _hibp_check(sender_email)
        results.extend(breach_results)

    # ── 4. Gravatar (always free, no key needed) ──────────────
    gravatar = _gravatar_lookup(sender_email)
    if gravatar:
        results.append(gravatar)

    # ── 5. Sherlock username search (local, no key needed) ────
    sherlock_results = _sherlock_search(username)
    results.extend(sherlock_results)

    # ── 6. Always add search URL links as fallback ────────────
    search_links = _build_search_links(sender_email, username, name_query)
    results.extend(search_links)

    return results


# ─────────────────────────────────────────────────────────────
# 1. FULLCONTACT API
# ─────────────────────────────────────────────────────────────

def _fullcontact_lookup(email: str) -> list:
    """
    FullContact Person API — matches email to real social profiles.
    100 free lookups/month. Returns actual confirmed profile URLs.
    API docs: https://platform.fullcontact.com/docs/apis/enrich/
    """
    results = []
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
            data     = resp.json()
            full_name= data.get("fullName", "")
            location = data.get("location", "")
            title    = data.get("title", "")
            org      = data.get("organization", "")

            # Profile picture
            avatar = data.get("avatar", "")
            if avatar:
                results.append({
                    "platform": "Profile Photo",
                    "url":      avatar,
                    "label":    "Profile photo via FullContact",
                    "type":     "real_profile",
                    "found":    True,
                    "data":     {"name": full_name, "location": location, "title": title},
                })

            # Social profiles
            for profile in data.get("details", {}).get("profiles", []):
                service = profile.get("service", "")
                url     = profile.get("url", "")
                username_fc = profile.get("username", "")
                if service and url:
                    results.append({
                        "platform": service.capitalize(),
                        "url":      url,
                        "label":    f"Confirmed {service} profile: @{username_fc}",
                        "type":     "real_profile",
                        "found":    True,
                        "data":     {"username": username_fc},
                    })

            # Employment
            for emp in data.get("details", {}).get("employment", []):
                company = emp.get("name", "")
                role    = emp.get("title", "")
                if company:
                    results.append({
                        "platform": "Employment",
                        "url":      f"https://www.linkedin.com/search/results/companies/?keywords={urllib.parse.quote_plus(company)}",
                        "label":    f"Works at {company} as {role}",
                        "type":     "enrichment",
                        "found":    True,
                        "data":     {"company": company, "role": role},
                    })

    except Exception as e:
        results.append({
            "platform": "FullContact",
            "url":      "",
            "label":    f"FullContact lookup failed: {str(e)[:60]}",
            "type":     "error",
            "found":    False,
            "data":     {},
        })
    return results


# ─────────────────────────────────────────────────────────────
# 2. HUNTER.IO ENRICHMENT
# ─────────────────────────────────────────────────────────────

def _hunter_lookup(email: str) -> list:
    """
    Hunter.io email finder — returns name, company, LinkedIn.
    25 free lookups/month.
    API docs: https://hunter.io/api-documentation/v2
    """
    results = []
    try:
        resp = requests.get(
            "https://api.hunter.io/v2/email-enrichment",
            params={"email": email, "api_key": HUNTER_KEY},
            timeout=10,
        )
        if resp.status_code == 200:
            d    = resp.json().get("data", {})
            name = f"{d.get('first_name','')} {d.get('last_name','')}".strip()
            org  = d.get("organization", "")
            linkedin = d.get("linkedin", "")
            twitter  = d.get("twitter", "")

            if name:
                results.append({
                    "platform": "Hunter.io",
                    "url":      f"https://hunter.io",
                    "label":    f"Name: {name}" + (f" | Company: {org}" if org else ""),
                    "type":     "enrichment",
                    "found":    True,
                    "data":     {"name": name, "org": org},
                })
            if linkedin:
                results.append({
                    "platform": "LinkedIn",
                    "url":      linkedin,
                    "label":    f"Confirmed LinkedIn via Hunter.io",
                    "type":     "real_profile",
                    "found":    True,
                    "data":     {},
                })
            if twitter:
                results.append({
                    "platform": "Twitter/X",
                    "url":      f"https://twitter.com/{twitter}",
                    "label":    f"Confirmed Twitter via Hunter.io: @{twitter}",
                    "type":     "real_profile",
                    "found":    True,
                    "data":     {"username": twitter},
                })
    except Exception as e:
        pass
    return results


# ─────────────────────────────────────────────────────────────
# 3. HAVEIBEENPWNED
# ─────────────────────────────────────────────────────────────

def _hibp_check(email: str) -> list:
    """
    Check if email appears in known data breaches.
    Requires HIBP API key ($3.50/month).
    """
    results = []
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            headers={
                "hibp-api-key":   HIBP_KEY,
                "User-Agent":     "ForensIQ-EmailAnalyzer",
            },
            timeout=10,
        )
        if resp.status_code == 200:
            breaches = resp.json()
            for breach in breaches[:5]:   # show top 5
                results.append({
                    "platform": f"Breach: {breach.get('Name','')}",
                    "url":      f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}",
                    "label":    f"Found in breach: {breach.get('Name','')} ({breach.get('BreachDate','')}) — {breach.get('DataClasses',[])}",
                    "type":     "breach",
                    "found":    True,
                    "data":     breach,
                })
        elif resp.status_code == 404:
            results.append({
                "platform": "HaveIBeenPwned",
                "url":      "",
                "label":    "No breaches found for this email",
                "type":     "breach",
                "found":    False,
                "data":     {},
            })
    except Exception:
        pass
    return results


# ─────────────────────────────────────────────────────────────
# 4. GRAVATAR (FREE — no key needed)
# ─────────────────────────────────────────────────────────────

def _gravatar_lookup(email: str) -> dict:
    """
    Gravatar uses an MD5 hash of the email to find a profile picture.
    Completely free — no API key needed.
    """
    try:
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=200"
        profile_url= f"https://www.gravatar.com/{email_hash}.json"

        # Check if profile exists
        resp = requests.get(profile_url, timeout=5)
        if resp.status_code == 200:
            data        = resp.json().get("entry", [{}])[0]
            display_name= data.get("displayName", "")
            return {
                "platform": "Gravatar",
                "url":      f"https://www.gravatar.com/{email_hash}",
                "label":    f"Gravatar profile found: {display_name}",
                "type":     "real_profile",
                "found":    True,
                "data":     {"avatar": avatar_url, "display_name": display_name},
            }
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────
# 5. SHERLOCK USERNAME SEARCH (FREE — local, no key)
# ─────────────────────────────────────────────────────────────

def _sherlock_search(username: str) -> list:
    """
    Uses the Sherlock project logic to check username across platforms.
    Sherlock checks if https://instagram.com/username exists (HTTP 200 = found).
    
    This is a lightweight version that checks the most important platforms.
    For full 400-platform search, install: pip install sherlock-project
    """
    results = []
    if not username or len(username) < 3:
        return results

    # Platforms where username URL returns 200 if profile exists
    PLATFORMS = [
        ("Instagram",  f"https://www.instagram.com/{username}/"),
        ("GitHub",     f"https://github.com/{username}"),
        ("Twitter/X",  f"https://twitter.com/{username}"),
        ("Reddit",     f"https://www.reddit.com/user/{username}"),
        ("TikTok",     f"https://www.tiktok.com/@{username}"),
        ("Pinterest",  f"https://www.pinterest.com/{username}/"),
        ("Medium",     f"https://medium.com/@{username}"),
        ("Keybase",    f"https://keybase.io/{username}"),
    ]

    headers = {"User-Agent": "Mozilla/5.0 (ForensIQ Investigator)"}

    for platform, url in PLATFORMS:
        try:
            resp = requests.get(url, headers=headers, timeout=5,
                                allow_redirects=True)
            found = resp.status_code == 200 and "Page Not Found" not in resp.text[:500]
            results.append({
                "platform": platform,
                "url":      url,
                "label":    f"{'✓ Profile EXISTS' if found else '✗ Not found'} on {platform}: @{username}",
                "type":     "real_profile" if found else "search_link",
                "found":    found,
                "data":     {"username": username, "http_status": resp.status_code},
            })
        except Exception:
            pass   # Timeout or network error — skip silently

    return results


# ─────────────────────────────────────────────────────────────
# 6. SEARCH URL LINKS (always built, no API needed)
# ─────────────────────────────────────────────────────────────

def _build_search_links(email: str, username: str, name_query: str) -> list:
    def enc(s): return urllib.parse.quote_plus(s)
    return [
        {
            "platform": "LinkedIn Search",
            "url":      f"https://www.linkedin.com/search/results/people/?keywords={enc(name_query)}",
            "label":    f"LinkedIn search for {name_query}",
            "type":     "search_link", "found": None, "data": {},
        },
        {
            "platform": "Facebook Search",
            "url":      f"https://www.facebook.com/search/top?q={enc(name_query)}",
            "label":    f"Facebook search for {name_query}",
            "type":     "search_link", "found": None, "data": {},
        },
        {
            "platform": "Google OSINT",
            "url":      f"https://www.google.com/search?q={enc(email)}+site%3Ainstagram.com+OR+site%3Alinkedin.com+OR+site%3Afacebook.com",
            "label":    f"Google OSINT search: {email} on social media",
            "type":     "search_link", "found": None, "data": {},
        },
    ]


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def format_social_links_text(links: list) -> str:
    """Format social links list to plain text for CSV/DB storage."""
    parts = []
    for l in links:
        if l.get("found") is True:
            parts.append(f"[FOUND] {l['platform']}: {l['url']}")
        elif l.get("found") is None:
            parts.append(f"[SEARCH] {l['platform']}: {l['url']}")
    return " | ".join(parts[:6])   # limit length


def get_confirmed_profiles(links: list) -> list:
    """Return only confirmed real profile links."""
    return [l for l in links if l.get("found") is True and l.get("type") == "real_profile"]


def get_breaches(links: list) -> list:
    """Return only breach records."""
    return [l for l in links if l.get("type") == "breach" and l.get("found") is True]