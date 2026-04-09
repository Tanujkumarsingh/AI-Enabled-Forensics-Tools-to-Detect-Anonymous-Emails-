# ============================================================
# FILE: src/forensic/spoof_detector.py
# ============================================================
import re

def detect_spoof(fields: dict) -> bool:
    """
    Detect email spoofing by comparing From, Reply-To, Return-Path domains.
    Returns True if spoofing is suspected.
    """
    from_email    = fields.get("sender_email", "").lower()
    reply_to      = fields.get("reply_to", "").lower()
    return_path   = fields.get("return_path", "").lower()
    sender_domain = fields.get("sender_domain", "").lower()

    def domain_of(addr):
        m = re.search(r"@([\w.\-]+)", addr)
        return m.group(1).lower() if m else ""

    rt_domain = domain_of(return_path)
    rp_domain = domain_of(reply_to)

    signals = []
    if rt_domain and sender_domain and rt_domain != sender_domain:
        signals.append("Return-Path domain mismatch")
    if rp_domain and sender_domain and rp_domain != sender_domain:
        signals.append("Reply-To domain mismatch")

    # Check if From display name contains a different email
    raw_from = fields.get("raw_headers", {}).get("From", "")
    embedded = re.findall(r"[\w.+\-]+@[\w.\-]+\.\w+", raw_from)
    if len(embedded) > 1:
        signals.append("Multiple emails in From header")

    return len(signals) > 0