# ============================================================
# FILE: src/utils/helpers.py
# PASTE AS: src/utils/helpers.py
# ============================================================
"""Common utility helpers used across all modules."""

import re
import os
import json
import datetime
import hashlib


def sanitize_filename(name: str) -> str:
    """Remove unsafe characters from a filename."""
    return re.sub(r"[^\w.\-_ ]", "_", name).strip()


def truncate(text: str, max_len: int = 100) -> str:
    """Truncate text with ellipsis."""
    return text if len(text) <= max_len else text[:max_len - 3] + "..."


def extract_email_address(raw: str) -> str:
    """Extract email address from 'Name <email@domain.com>' format."""
    match = re.search(r"[\w.+\-]+@[\w.\-]+\.\w+", raw)
    return match.group(0) if match else raw.strip()


def extract_domain(email_addr: str) -> str:
    """Get domain from an email address."""
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower().strip()
    return ""


def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[\w.+\-]+@[\w.\-]+\.\w{2,}$", email))


def is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def is_private_ip(ip: str) -> bool:
    return bool(re.match(
        r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)", ip
    ))


def sha256(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def utc_now_human() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def safe_json(data) -> str:
    return json.dumps(data, default=str, indent=2)


def ensure_dirs(*paths):
    """Create multiple directories if they don't exist."""
    for path in paths:
        os.makedirs(path, exist_ok=True)


def risk_level(score: float) -> str:
    if score >= 70: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"


def risk_color(score: float) -> str:
    """Return a CSS color string based on risk score."""
    if score >= 70: return "#ff4c6a"
    if score >= 50: return "#f0a500"
    if score >= 30: return "#f0d000"
    return "#39ff14"


def clean_text(text: str) -> str:
    """Remove excessive whitespace and control characters."""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def count_words(text: str) -> int:
    return len(text.split()) if text else 0


def flatten_list(nested: list) -> list:
    result = []
    for item in nested:
        if isinstance(item, list):
            result.extend(flatten_list(item))
        else:
            result.append(item)
    return result