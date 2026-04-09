# ============================================================
# FILE: src/preprocessing/header_parser.py
# ============================================================
import re

def extract_headers(msg) -> dict:
    """Return all headers as a flat dict."""
    return {k: str(v) for k, v in msg.items()}

def extract_ip_chain(msg) -> list:
    """Parse all Received headers and extract public IPs in order."""
    received = msg.get_all("Received") or []
    ips = []
    for header in received:
        found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(header))
        for ip in found:
            if not _is_private(ip) and ip not in ips:
                ips.append(ip)
    return ips

def get_sender_ip(msg) -> str:
    """Return the most likely sender IP (last in chain = first hop)."""
    chain = extract_ip_chain(msg)
    return chain[-1] if chain else ""

def get_x_originating_ip(msg) -> str:
    return str(msg.get("X-Originating-IP", "") or "")

def get_reply_to(msg) -> str:
    return str(msg.get("Reply-To", "") or "")

def get_return_path(msg) -> str:
    return str(msg.get("Return-Path", "") or "")

def get_message_id(msg) -> str:
    return str(msg.get("Message-ID", "") or "")

def get_x_mailer(msg) -> str:
    return str(msg.get("X-Mailer", "") or "")

def _is_private(ip: str) -> bool:
    return bool(re.match(
        r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)", ip
    ))