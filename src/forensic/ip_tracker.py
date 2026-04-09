# ============================================================
# FILE: src/forensic/ip_tracker.py
# PASTE AS: src/forensic/ip_tracker.py
# ============================================================
"""
IP chain extractor from email Received headers.

Handles the most common real-world case:
  Gmail, Outlook, Yahoo, ProtonMail and other webmail providers
  STRIP the sender's real IP from headers. This module detects
  this situation and returns useful information instead of blank.
"""

import re

# ── Known webmail providers that hide sender IP ───────────────
# These are the IP ranges / hostname patterns of their mail servers.
# If ALL IPs in the chain belong to one of these, the real IP is hidden.
WEBMAIL_PROVIDERS = {
    "gmail":      {
        "ip_ranges":  [r"^209\.85\.", r"^74\.125\.", r"^173\.194\.",
                       r"^108\.177\.", r"^142\.250\.", r"^172\.217\."],
        "host_patterns": [r"mail[-\w]*\.google\.com", r"smtp\.gmail\.com",
                          r"googlemail\.com"],
        "label": "Gmail / Google Workspace",
        "note":  "Gmail hides the sender's real IP. Only Google mail server IPs are visible.",
    },
    "outlook":    {
        "ip_ranges":  [r"^40\.", r"^52\.", r"^104\.", r"^13\."],
        "host_patterns": [r"mail[-\w]*\.protection\.outlook\.com",
                          r"smtp\.office365\.com", r"hotmail-com\.olc\.protection\.outlook\.com"],
        "label": "Microsoft Outlook / Office 365",
        "note":  "Outlook/Office365 hides the sender's real IP.",
    },
    "yahoo":      {
        "ip_ranges":  [r"^66\.163\.", r"^98\.136\.", r"^67\.195\.",
                       r"^74\.6\."],
        "host_patterns": [r"mail\.yahoo\.com", r"smtp\.mail\.yahoo\.com",
                          r"yahoo\.com"],
        "label": "Yahoo Mail",
        "note":  "Yahoo Mail hides the sender's real IP.",
    },
    "protonmail": {
        "ip_ranges":  [r"^185\.70\.", r"^185\.159\.", r"^5\.199\."],
        "host_patterns": [r"protonmail\.ch", r"mail\.protonmail\.com",
                          r"proton\.me"],
        "label": "ProtonMail (encrypted, anonymous)",
        "note":  "ProtonMail hides sender IP by design for privacy.",
    },
    "icloud":     {
        "ip_ranges":  [r"^17\."],
        "host_patterns": [r"apple\.com", r"icloud\.com"],
        "label": "Apple iCloud Mail",
        "note":  "iCloud Mail hides the sender's real IP.",
    },
    "zoho":       {
        "host_patterns": [r"zoho\.com", r"zohocorp\.com"],
        "label": "Zoho Mail",
        "note":  "Zoho Mail hides the sender's real IP.",
    },
}


def track_ips(msg) -> dict:
    """
    Build a full IP hop chain from email Received headers.

    Returns:
    {
      "all_ips":        list of public IPs found
      "sender_ip":      first (likely sender-closest) public IP
      "hop_count":      number of Received headers
      "chain":          list of hop dicts
      "provider":       detected mail provider name (if webmail)
      "provider_note":  explanation of why IP may be hidden
      "ip_hidden":      True if sender IP is hidden by webmail
      "mail_server_ips":IPs found that belong to mail provider
    }
    """
    received  = msg.get_all("Received") or []
    hops      = []
    all_ips   = []
    raw_hosts = []

    for header in reversed(received):   # oldest = first hop
        header_str = str(header)
        ips        = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", header_str)
        public     = [ip for ip in ips if not _is_private(ip)]

        by_match   = re.search(r"\bby\s+([\w.\-]+)",   header_str, re.IGNORECASE)
        from_match = re.search(r"\bfrom\s+([\w.\-]+)", header_str, re.IGNORECASE)

        by_host   = by_match.group(1).lower()   if by_match   else ""
        from_host = from_match.group(1).lower() if from_match else ""

        raw_hosts.extend([by_host, from_host])
        hops.append({
            "from_host": from_host,
            "by_host":   by_host,
            "ips":       public,
            "raw":       header_str[:300],
        })
        for ip in public:
            if ip not in all_ips:
                all_ips.append(ip)

    # Also check X-Originating-IP (some older clients include real IP here)
    x_orig = str(msg.get("X-Originating-IP", "") or "").strip()
    x_orig = re.sub(r"[\[\]]", "", x_orig).strip()
    if x_orig and _is_valid_ip(x_orig) and not _is_private(x_orig):
        if x_orig not in all_ips:
            all_ips.insert(0, x_orig)

    # Also check X-Forwarded-For
    x_fwd = str(msg.get("X-Forwarded-For", "") or "").strip()
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", x_fwd):
        if not _is_private(ip) and ip not in all_ips:
            all_ips.insert(0, ip)

    # ── Detect webmail provider ───────────────────────────────
    provider       = ""
    provider_label = ""
    provider_note  = ""
    ip_hidden      = False
    mail_server_ips= []

    for prov_key, prov_info in WEBMAIL_PROVIDERS.items():
        matched = False

        # Check hostname patterns
        for pattern in prov_info.get("host_patterns", []):
            if any(re.search(pattern, h, re.IGNORECASE)
                   for h in raw_hosts if h):
                matched = True
                break

        # Check IP ranges
        if not matched:
            for ip in all_ips:
                for rng in prov_info.get("ip_ranges", []):
                    if re.match(rng, ip):
                        matched = True
                        mail_server_ips.append(ip)
                        break

        if matched:
            provider       = prov_key
            provider_label = prov_info["label"]
            provider_note  = prov_info["note"]
            ip_hidden      = True
            break

    # ── If all IPs belong to a known provider → treat as hidden ─
    # The real sender IP is behind the provider's servers
    usable_ips = [
        ip for ip in all_ips
        if not _is_known_provider_ip(ip)
    ]

    return {
        "all_ips":         all_ips,
        "usable_ips":      usable_ips,
        "sender_ip":       usable_ips[0] if usable_ips else (all_ips[0] if all_ips else ""),
        "hop_count":       len(hops),
        "chain":           hops,
        "provider":        provider,
        "provider_label":  provider_label,
        "provider_note":   provider_note,
        "ip_hidden":       ip_hidden,
        "mail_server_ips": mail_server_ips,
        "x_originating_ip": x_orig,
    }


# ── Helpers ───────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    return bool(re.match(
        r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)", ip
    ))

def _is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def _is_known_provider_ip(ip: str) -> bool:
    """Check if an IP belongs to a known webmail provider range."""
    for prov_info in WEBMAIL_PROVIDERS.values():
        for rng in prov_info.get("ip_ranges", []):
            if re.match(rng, ip):
                return True
    return False