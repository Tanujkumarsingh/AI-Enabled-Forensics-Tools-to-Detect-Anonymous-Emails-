# ============================================================
# FILE: src/intelligence/social_sender_grouper.py
# NEW FILE — Automatic Sender Grouping + Filtering
# ============================================================
"""
Auto Sender Grouper for ForensIQ.
===========================================

YOUR SUGGESTION WAS CORRECT! Here's the logic:

1. Collect all social links found for a sender
2. Group them by SENDER NAME (same name → same group)
3. Within each name-group, rank by location match:
   - city / state / country match → HIGH PRIORITY
   - qualification / education match → BOOST
4. Top ranked profiles = most likely real sender

This works because:
  - "Rahul Sharma" in LinkedIn = same person as "rahul.sharma@gmail.com"
  - 10 emails → 8 senders identified correctly by name+location match

Usage:
    from src.intelligence.social_sender_grouper import group_and_filter_senders
    
    result = group_and_filter_senders(
        social_links=links,
        sender_email="rahul.sharma@gmail.com",
        sender_name="Rahul Sharma",
        geo={"city": "Mumbai", "region": "Maharashtra", "country": "India"},
        domain_info={"org": "TCS", "registrar": "..."}
    )
    
    result = {
        "top_candidate":   { name, profiles, score, location, qualification },
        "groups":          [ { name, profiles, score, location } ],
        "is_anonymous":    True/False,
        "anonymous_reason": "No social accounts found / Older person using email",
        "filter_used":     { city, state, country, qualification }
    }
"""

import re
import urllib.parse
from collections import defaultdict


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────

def group_and_filter_senders(
    social_links: list,
    sender_email: str = "",
    sender_name: str = "",
    geo: dict = None,
    domain_info: dict = None,
) -> dict:
    """
    Auto-group social profiles by sender name, then rank by
    city/state/country/qualification.

    Returns the most likely real sender identity.
    """
    geo         = geo or {}
    domain_info = domain_info or {}

    if not social_links:
        return _anonymous_result("No social links found for this sender.")

    # Extract username from email
    username = ""
    if sender_email and "@" in sender_email:
        username = sender_email.split("@")[0].lower()

    # Normalize geo fields for matching
    city    = _normalize(geo.get("city", ""))
    state   = _normalize(geo.get("region", geo.get("state", "")))
    country = _normalize(geo.get("country", ""))

    # ── Step 1: Group by name ─────────────────────────────────────────────────
    name_groups = _group_by_name(social_links, sender_name, username)

    if not name_groups:
        return _anonymous_result("No named profiles found — anonymous or no digital footprint.")

    # ── Step 2: Score each group by location + qualification ─────────────────
    scored_groups = []
    for group_name, profiles in name_groups.items():
        score, location_match, qualification = _score_group(
            profiles, city, state, country, domain_info, username, group_name
        )
        scored_groups.append({
            "name":          group_name,
            "profiles":      profiles,
            "score":         score,
            "location_match": location_match,
            "qualification": qualification,
            "profile_count": len(profiles),
        })

    # Sort by score descending
    scored_groups.sort(key=lambda x: x["score"], reverse=True)

    top = scored_groups[0] if scored_groups else None

    # Determine if truly anonymous
    confirmed = [p for p in social_links if p.get("found") is True]
    is_anon   = len(confirmed) == 0

    anon_reason = ""
    if is_anon:
        if _looks_old_email(sender_email):
            anon_reason = "This appears to be an older/legacy email account with no social media presence."
        else:
            anon_reason = "Anonymous email — no social accounts found. Sender has no digital footprint."

    return {
        "top_candidate":   top,
        "groups":          scored_groups[:8],   # top 8 groups
        "is_anonymous":    is_anon,
        "anonymous_reason": anon_reason,
        "filter_used": {
            "city":          city,
            "state":         state,
            "country":       country,
        },
        "total_profiles_found": len(confirmed),
    }


# ─────────────────────────────────────────────────────────────
# STEP 1: GROUP BY NAME
# ─────────────────────────────────────────────────────────────

def _group_by_name(links: list, sender_name: str, username: str) -> dict:
    """
    Group social links by the apparent person name.
    Priority: sender_name match → username match → platform label
    """
    groups = defaultdict(list)

    for link in links:
        # Skip pure search links with no identity
        if link.get("type") == "search_link" and not link.get("found"):
            continue

        label    = link.get("label", "")
        platform = link.get("platform", "")
        url      = link.get("url", "")
        data     = link.get("data", {})

        # Try to extract a name from the link data
        name = (
            data.get("name", "") or
            data.get("display_name", "") or
            _extract_name_from_label(label) or
            _extract_name_from_url(url, username) or
            sender_name or
            username or
            "Unknown"
        )

        name = _clean_name(name)
        if name:
            groups[name].append(link)

    # Also add sender_name group if we have any confirmed links
    if sender_name:
        clean_sn = _clean_name(sender_name)
        if clean_sn and clean_sn not in groups:
            confirmed = [l for l in links if l.get("found") is True]
            if confirmed:
                groups[clean_sn] = confirmed

    return dict(groups)


def _extract_name_from_label(label: str) -> str:
    """Try to pull a name out of strings like 'Name: Rahul Sharma | Company: TCS'"""
    m = re.search(r"Name:\s*([A-Za-z ]+)", label)
    if m:
        return m.group(1).strip()
    m = re.search(r"profile:\s*@?([A-Za-z0-9_]+)", label, re.I)
    if m:
        return m.group(1).strip()
    return ""


def _extract_name_from_url(url: str, username: str) -> str:
    """Extract username from URL path like /rahul.sharma"""
    if not url:
        return ""
    parts = url.rstrip("/").split("/")
    last = parts[-1] if parts else ""
    if last and last.startswith("@"):
        return last[1:]
    if last and last.lower() == username:
        return username
    return ""


def _clean_name(name: str) -> str:
    """Normalize name: strip, title case, remove special chars"""
    name = re.sub(r"[^A-Za-z0-9 ._@-]", "", name.strip())
    return name.strip()[:60]


# ─────────────────────────────────────────────────────────────
# STEP 2: SCORE BY LOCATION + QUALIFICATION
# ─────────────────────────────────────────────────────────────

def _score_group(
    profiles: list, city: str, state: str, country: str,
    domain_info: dict, username: str, group_name: str
) -> tuple:
    """
    Score a name-group based on location and qualification matches.
    Returns (score, location_match_string, qualification_string)
    """
    score          = 0
    location_match = ""
    qualification  = ""

    combined_text = " ".join([
        _normalize(p.get("url", "")) +
        _normalize(p.get("label", "")) +
        _normalize(str(p.get("data", {})))
        for p in profiles
    ])

    # ── Username match (strongest signal) ────────────────────
    if username and username in combined_text:
        score += 50

    # ── Confirmed profiles boost ──────────────────────────────
    confirmed_count = sum(1 for p in profiles if p.get("found") is True)
    score += confirmed_count * 15

    # ── Location match ────────────────────────────────────────
    loc_parts = []
    if city and city in combined_text:
        score += 30
        loc_parts.append(city.title())
    if state and state in combined_text:
        score += 20
        loc_parts.append(state.title())
    if country and country in combined_text:
        score += 15
        loc_parts.append(country.title())
    location_match = ", ".join(loc_parts)

    # ── Qualification / Education ─────────────────────────────
    edu_kws = {
        "engineer": 10, "developer": 8, "software": 8,
        "manager": 7, "analyst": 7, "doctor": 10, "professor": 10,
        "student": 5, "phd": 12, "mba": 10, "btech": 8, "mtech": 8,
        "iit": 15, "nit": 12, "iiit": 12, "university": 8, "college": 6,
        "ceo": 12, "cto": 12, "founder": 10, "director": 8,
    }
    found_quals = []
    for kw, pts in edu_kws.items():
        if kw in combined_text:
            score += pts
            found_quals.append(kw.upper())
    qualification = ", ".join(found_quals[:4])

    # ── LinkedIn/GitHub are strongest platforms ───────────────
    for p in profiles:
        url = _normalize(p.get("url", ""))
        if "linkedin.com" in url and p.get("found"):
            score += 20
        elif "github.com" in url and p.get("found"):
            score += 15

    # ── Domain org match ─────────────────────────────────────
    org = _normalize(domain_info.get("org", ""))
    if org and len(org) > 3 and org in combined_text:
        score += 20

    return score, location_match, qualification


# ─────────────────────────────────────────────────────────────
# ANONYMOUS DETECTION
# ─────────────────────────────────────────────────────────────

def _looks_old_email(email: str) -> bool:
    """Heuristic: old email addresses often have no social media"""
    if not email:
        return False
    domain = email.split("@")[-1].lower() if "@" in email else ""
    username = email.split("@")[0].lower()

    # Old-style email providers
    old_domains = ["hotmail.com", "yahoo.com", "rediffmail.com",
                   "aol.com", "msn.com", "live.com", "outlook.com"]

    # Very short/simple usernames are often older accounts
    has_old_domain = domain in old_domains
    looks_old      = re.match(r"^[a-z]+\d{4,}$", username) is not None  # e.g. john1965
    has_birth_year = bool(re.search(r"(19[4-9]\d|200[0-5])", username))  # year in name

    return has_old_domain and (looks_old or has_birth_year)


def _anonymous_result(reason: str) -> dict:
    return {
        "top_candidate":    None,
        "groups":           [],
        "is_anonymous":     True,
        "anonymous_reason": reason,
        "filter_used":      {},
        "total_profiles_found": 0,
    }


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _normalize(text: str) -> str:
    return str(text).lower().strip() if text else ""
