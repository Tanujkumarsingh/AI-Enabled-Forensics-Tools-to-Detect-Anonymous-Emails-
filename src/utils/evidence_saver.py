# ============================================================
# FILE: src/utils/evidence_saver.py
# PASTE AS: src/utils/evidence_saver.py
# ============================================================
"""
Saves forensic evidence to structured folders:
  evidence/metadata/  — email metadata JSON
  evidence/ips/       — IP chain and geolocation
  evidence/urls/      — extracted URLs
  evidence/hashes/    — attachment SHA-256 hashes
"""

import os
import json
import datetime

EVIDENCE_DIR = "evidence"


def save_evidence(fields: dict, forensic: dict) -> dict:
    """
    Persist all forensic findings to evidence folder.
    Returns dict of saved file paths.
    """
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    email_id  = fields.get("email_hash_sha256", "unknown")[:12]
    prefix    = f"{timestamp}_{email_id}"
    saved     = {}

    # ── Metadata ───────────────────────────────────────────
    meta_dir = os.path.join(EVIDENCE_DIR, "metadata")
    os.makedirs(meta_dir, exist_ok=True)
    meta_path = os.path.join(meta_dir, f"{prefix}_metadata.json")
    meta = {
        "subject":        fields.get("subject",        ""),
        "sender_email":   fields.get("sender_email",   ""),
        "sender_domain":  fields.get("sender_domain",  ""),
        "date_sent":      fields.get("date_sent",      ""),
        "message_id":     fields.get("message_id",     ""),
        "x_mailer":       fields.get("x_mailer",       ""),
        "mime_version":   fields.get("mime_version",   ""),
        "x_originating_ip": fields.get("x_originating_ip", ""),
        "email_hash_sha256": fields.get("email_hash_sha256",""),
        "source_type":    fields.get("source_type",    ""),
        "autopsy_timestamp": fields.get("autopsy_timestamp",""),
        "spf_result":     fields.get("spf_result",     ""),
        "dkim_result":    fields.get("dkim_result",    ""),
        "spoof_detected": fields.get("spoof_detected", False),
        "is_anonymous":   fields.get("is_anonymous",   False),
        "is_temp_mail":   fields.get("is_temp_mail",   False),
    }
    _write_json(meta_path, meta)
    saved["metadata"] = meta_path

    # ── IPs ────────────────────────────────────────────────
    ip_dir = os.path.join(EVIDENCE_DIR, "ips")
    os.makedirs(ip_dir, exist_ok=True)
    ip_path = os.path.join(ip_dir, f"{prefix}_ips.json")
    ip_data = {
        "ip_chain":    fields.get("ip_addresses", []),
        "geolocation": forensic.get("geolocation", ""),
        "isp":         forensic.get("isp",         ""),
        "as_number":   forensic.get("as",          ""),
        "proxy":       forensic.get("proxy",        False),
        "hosting":     forensic.get("hosting",      False),
    }
    _write_json(ip_path, ip_data)
    saved["ips"] = ip_path

    # ── URLs ───────────────────────────────────────────────
    url_dir = os.path.join(EVIDENCE_DIR, "urls")
    os.makedirs(url_dir, exist_ok=True)
    url_path = os.path.join(url_dir, f"{prefix}_urls.json")
    url_data = {
        "all_urls":      fields.get("urls_found",      []),
        "suspicious":    fields.get("suspicious_urls", []),
        "url_count":     fields.get("url_count",       0),
    }
    _write_json(url_path, url_data)
    saved["urls"] = url_path

    # ── Hashes ─────────────────────────────────────────────
    hash_dir = os.path.join(EVIDENCE_DIR, "hashes")
    os.makedirs(hash_dir, exist_ok=True)
    hash_path = os.path.join(hash_dir, f"{prefix}_hashes.json")
    hash_data = {
        "email_sha256":       fields.get("email_hash_sha256", ""),
        "attachment_hashes":  fields.get("attachment_hashes", []),
        "attachment_names":   fields.get("attachment_names",  []),
    }
    _write_json(hash_path, hash_data)
    saved["hashes"] = hash_path

    return saved


def _write_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)