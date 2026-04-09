# ============================================================
# FILE: src/utils/splunk_logger.py
# PASTE AS: src/utils/splunk_logger.py
# ============================================================
"""
Splunk SIEM integration via HTTP Event Collector (HEC).
Set these environment variables to enable:
  SPLUNK_HEC_URL   = https://your-splunk-host:8088/services/collector
  SPLUNK_HEC_TOKEN = your-hec-token
"""

import os
import json
import datetime
import requests

SPLUNK_URL   = os.environ.get("SPLUNK_HEC_URL",   "")
SPLUNK_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN",  "")


def log_to_splunk(fields: dict, forensic: dict) -> bool:
    """
    Send forensic event to Splunk HEC.
    Returns True on success, False on failure or if not configured.
    """
    if not SPLUNK_URL or not SPLUNK_TOKEN:
        # Splunk not configured — write to local log file instead
        _log_local(fields, forensic)
        return False

    event = _build_event(fields, forensic)
    try:
        resp = requests.post(
            SPLUNK_URL,
            headers={
                "Authorization": f"Splunk {SPLUNK_TOKEN}",
                "Content-Type":  "application/json",
            },
            json={"event": event, "sourcetype": "forensiq_email", "source": "ForensIQ"},
            timeout=5,
            verify=False,
        )
        return resp.status_code in (200, 201)
    except Exception as e:
        print(f"[splunk_logger] Failed to send to Splunk: {e}")
        _log_local(fields, forensic)
        return False


def _build_event(fields: dict, forensic: dict) -> dict:
    return {
        "timestamp":      datetime.datetime.utcnow().isoformat(),
        "source_type":    fields.get("source_type",    ""),
        "sender_email":   fields.get("sender_email",   ""),
        "sender_domain":  fields.get("sender_domain",  ""),
        "subject":        fields.get("subject",         "")[:200],
        "ip_chain":       forensic.get("ip_chain",     ""),
        "geolocation":    forensic.get("geolocation",  ""),
        "isp":            forensic.get("isp",           ""),
        "spf":            forensic.get("spf",           ""),
        "dkim":           forensic.get("dkim",          ""),
        "spoof_detected": forensic.get("spoof",         False),
        "risk_score":     forensic.get("risk_score",    0),
        "classification": forensic.get("classification",""),
        "url_count":      fields.get("url_count",       0),
        "attachment_count":fields.get("attachment_count",0),
        "is_temp_mail":   fields.get("is_temp_mail",    False),
        "email_hash":     fields.get("email_hash_sha256",""),
    }


def _log_local(fields: dict, forensic: dict):
    """Fallback: write event to local log file."""
    log_dir  = os.path.join("evidence", "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "forensiq_events.log")
    event    = _build_event(fields, forensic)
    with open(log_file, "a") as f:
        f.write(json.dumps(event) + "\n")