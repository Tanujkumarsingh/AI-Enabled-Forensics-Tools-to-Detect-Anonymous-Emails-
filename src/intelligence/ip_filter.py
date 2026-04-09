# ============================================================
# FILE: src/intelligence/ip_filter.py
# PASTE AS: src/intelligence/ip_filter.py
# ============================================================
import re

PRIVATE_RANGES = [
    r"^10\.",
    r"^172\.(1[6-9]|2[0-9]|3[01])\.",
    r"^192\.168\.",
    r"^127\.",
    r"^0\.",
    r"^169\.254\.",
    r"^::1$",
    r"^fc00:",
    r"^fe80:",
]


def is_private(ip: str) -> bool:
    return any(re.match(p, ip.strip()) for p in PRIVATE_RANGES)


def is_public(ip: str) -> bool:
    return not is_private(ip)


def filter_public_ips(ips: list) -> list:
    """Return only public (non-private) IPs from a list."""
    return [ip for ip in ips if is_public(ip)]


def filter_private_ips(ips: list) -> list:
    """Return only private IPs from a list."""
    return [ip for ip in ips if is_private(ip)]


def deduplicate_ips(ips: list) -> list:
    """Remove duplicates while preserving order."""
    return list(dict.fromkeys(ips))


def clean_ip_list(ips: list) -> list:
    """Filter public + deduplicate."""
    return deduplicate_ips(filter_public_ips(ips))