# ============================================================
# FILE: src/ingestion/manual_input.py
# PASTE AS: src/ingestion/manual_input.py
# ============================================================
"""
Processes manually entered email data from the UI form.
Validates and structures it for the forensic pipeline.
"""

import re


def process_manual_input(subject: str,
                          sender:  str,
                          body:    str,
                          urls:    list = None,
                          attachments: list = None) -> dict:
    """
    Validate and structure manual email input.
    Returns cleaned dict ready for EmailAutopsy.autopsy_from_manual()
    """
    subject     = (subject     or "").strip()
    sender      = (sender      or "").strip()
    body        = (body        or "").strip()
    urls        = urls         or []
    attachments = attachments  or []

    errors = []
    if not body:
        errors.append("Email body is required.")
    if sender and not _is_valid_email(sender):
        errors.append(f"Sender email format invalid: {sender}")

    # Clean URLs
    clean_urls = []
    for u in urls:
        u = u.strip()
        if u and re.match(r"https?://", u):
            clean_urls.append(u)

    return {
        "valid":       len(errors) == 0,
        "errors":      errors,
        "subject":     subject,
        "sender":      sender,
        "body":        body,
        "urls":        clean_urls,
        "attachments": attachments,
        "source_type": "manual",
    }


def _is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[\w.+\-]+@[\w.\-]+\.\w{2,}$", email))