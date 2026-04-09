# ============================================================
# FILE: src/intelligence/email_verifier.py
# PASTE AS: src/intelligence/email_verifier.py
# ============================================================
"""
SMTP Email Existence Verifier + Domain WHOIS Enrichment

Does two things:
  1. Verifies if an email address actually EXISTS on the mail server
     using SMTP protocol (RCPT TO handshake) — no email is sent.

  2. Returns full domain WHOIS data including creation date,
     registrar, organisation, nameservers, expiry.

SMTP Verification works like this:
  Step 1 → DNS MX lookup  (find mail server for domain)
  Step 2 → TCP connect    (connect to mail server port 25)
  Step 3 → HELO           (introduce ourselves)
  Step 4 → MAIL FROM      (fake sender)
  Step 5 → RCPT TO        (ask about target email)
  Step 6 → Read response
    250 = email EXISTS
    550 = email does NOT exist
    Other = server blocked check (catch-all / greylisting)
  Step 7 → QUIT           (disconnect cleanly)

Limitations:
  - Some servers use "catch-all" (accept all emails → always 250)
  - Some servers block port 25 connections from non-mail IPs
  - Gmail, Yahoo, Outlook block SMTP verification entirely
  - Result "unknown" means the server refused to confirm either way
"""

import socket
import smtplib
import dns.resolver
import datetime
import re
import os

SMTP_TIMEOUT   = 10    # seconds per connection attempt
FROM_EMAIL     = "verify@forensiq-check.com"   # fake sender (never actually sent)


# ─────────────────────────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────────────────────────

def verify_email_full(email: str) -> dict:
    """
    Full email verification: SMTP check + WHOIS domain info.

    Returns:
    {
      "email":              str,
      "domain":             str,

      # SMTP verification result
      "smtp_exists":        True | False | None,
      "smtp_status":        "exists" | "not_exists" | "unknown" | "catch_all" | "blocked",
      "smtp_code":          int (SMTP response code),
      "smtp_message":       str (server response message),
      "smtp_server":        str (MX server used),
      "smtp_note":          str (human readable explanation),

      # MX Records
      "mx_records":         list of str,
      "mx_found":           bool,

      # WHOIS domain info
      "domain_created":     str (date),
      "domain_age":         str (e.g. "27 yr 3 mo"),
      "domain_expires":     str (date),
      "domain_updated":     str (date),
      "domain_registrar":   str,
      "domain_org":         str,
      "domain_nameservers": list,
      "domain_status":      list,
      "whois_error":        str,

      # Summary
      "summary":            str,
      "checked_at":         str (UTC ISO timestamp),
    }
    """
    if not email or "@" not in email:
        return {"error": "Invalid email address", "email": email}

    parts  = email.strip().lower().split("@")
    domain = parts[1]

    result = {
        "email":              email,
        "domain":             domain,
        # SMTP
        "smtp_exists":        None,
        "smtp_status":        "unknown",
        "smtp_code":          0,
        "smtp_message":       "",
        "smtp_server":        "",
        "smtp_note":          "",
        # MX
        "mx_records":         [],
        "mx_found":           False,
        # WHOIS
        "domain_created":     "",
        "domain_age":         "",
        "domain_expires":     "",
        "domain_updated":     "",
        "domain_registrar":   "",
        "domain_org":         "",
        "domain_nameservers": [],
        "domain_status":      [],
        "whois_error":        "",
        # Summary
        "summary":            "",
        "checked_at":         datetime.datetime.utcnow().isoformat() + "Z",
    }

    # ── Step 1: MX Records ────────────────────────────────────
    mx_host = _get_mx_record(domain, result)

    # ── Step 2: SMTP Verification ─────────────────────────────
    if mx_host:
        _smtp_verify(email, mx_host, result)
    else:
        result["smtp_status"]  = "blocked"
        result["smtp_note"]    = "No MX records found — domain may not accept email."
        result["smtp_exists"]  = False

    # ── Step 3: WHOIS Domain Info ─────────────────────────────
    _whois_lookup(domain, result)

    # ── Step 4: Build summary ─────────────────────────────────
    result["summary"] = _build_summary(result)

    return result


# ─────────────────────────────────────────────────────────────
# MX RECORD LOOKUP
# ─────────────────────────────────────────────────────────────

def _get_mx_record(domain: str, result: dict) -> str:
    """
    DNS MX lookup. Returns the highest priority mail server hostname.
    """
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8)
        mx_list = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0]
        )
        result["mx_records"] = [f"{pref} {host}" for pref, host in mx_list]
        result["mx_found"]   = True

        if mx_list:
            return mx_list[0][1]   # highest priority MX host
    except dns.resolver.NXDOMAIN:
        result["smtp_note"] = "Domain does not exist (NXDOMAIN)"
        result["smtp_exists"] = False
    except dns.resolver.NoAnswer:
        result["smtp_note"] = "No MX records found for this domain"
    except Exception as e:
        result["smtp_note"] = f"MX lookup failed: {str(e)[:80]}"
    return ""


# ─────────────────────────────────────────────────────────────
# SMTP VERIFICATION
# ─────────────────────────────────────────────────────────────

# Domains that are known to block SMTP verification
BLOCKED_DOMAINS = {
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.co.in", "yahoo.co.uk",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me",
    "zoho.com",
}

def _smtp_verify(email: str, mx_host: str, result: dict) -> None:
    """
    Connect to the MX server and perform RCPT TO check.
    Updates result dict in place.
    """
    domain = email.split("@")[1].lower()

    # Known blockers — skip SMTP, mark as unknown
    if domain in BLOCKED_DOMAINS:
        result["smtp_status"]  = "blocked"
        result["smtp_server"]  = mx_host
        result["smtp_note"]    = (
            f"{domain} does not allow SMTP verification. "
            f"These providers block external checks to protect user privacy. "
            f"Account existence cannot be confirmed without login."
        )
        result["smtp_exists"]  = None
        return

    result["smtp_server"] = mx_host

    try:
        # Connect to port 25 (SMTP)
        with smtplib.SMTP(timeout=SMTP_TIMEOUT) as smtp:
            smtp.connect(mx_host, 25)
            smtp.ehlo_or_helo_if_needed()

            # MAIL FROM with a fake sender
            code, msg = smtp.mail(FROM_EMAIL)
            if code not in (250, 251):
                result["smtp_status"]  = "blocked"
                result["smtp_note"]    = f"Server rejected MAIL FROM (code {code})"
                result["smtp_exists"]  = None
                smtp.quit()
                return

            # RCPT TO — this is where the server tells us if the address exists
            code, msg = smtp.rcpt(email)
            msg_str   = msg.decode("utf-8", errors="replace") if isinstance(msg, bytes) else str(msg)

            result["smtp_code"]    = code
            result["smtp_message"] = msg_str[:200]

            if code == 250:
                # 250 = Accepted → email EXISTS (or catch-all)
                # Check for catch-all by trying a random address
                fake_email   = f"this_address_cannot_exist_xyz123@{domain}"
                code2, msg2  = smtp.rcpt(fake_email)
                if code2 == 250:
                    # Server accepts everything → catch-all, can't confirm
                    result["smtp_status"] = "catch_all"
                    result["smtp_exists"] = None
                    result["smtp_note"]   = (
                        "This mail server accepts ALL email addresses "
                        "(catch-all policy). Cannot confirm if this specific "
                        "address exists."
                    )
                else:
                    # Real confirmation — address exists
                    result["smtp_status"] = "exists"
                    result["smtp_exists"] = True
                    result["smtp_note"]   = (
                        "Mail server confirmed this email address EXISTS. "
                        "SMTP response 250 OK received."
                    )

            elif code in (550, 551, 552, 553, 554):
                # 550 = User unknown → email does NOT exist
                result["smtp_status"] = "not_exists"
                result["smtp_exists"] = False
                result["smtp_note"]   = (
                    f"Mail server rejected this address (code {code}). "
                    f"Email does NOT exist on this server."
                )

            elif code in (421, 450, 451, 452):
                # Temporary failure
                result["smtp_status"] = "unknown"
                result["smtp_exists"] = None
                result["smtp_note"]   = (
                    f"Server returned temporary failure (code {code}). "
                    f"Try again later."
                )

            else:
                result["smtp_status"] = "unknown"
                result["smtp_exists"] = None
                result["smtp_note"]   = (
                    f"Unexpected server response (code {code}): {msg_str[:100]}"
                )

            smtp.quit()

    except smtplib.SMTPConnectError as e:
        result["smtp_status"] = "blocked"
        result["smtp_note"]   = f"Could not connect to mail server: {str(e)[:100]}"
        result["smtp_exists"] = None

    except smtplib.SMTPServerDisconnected:
        result["smtp_status"] = "blocked"
        result["smtp_note"]   = "Mail server disconnected before verification completed."
        result["smtp_exists"] = None

    except socket.timeout:
        result["smtp_status"] = "blocked"
        result["smtp_note"]   = f"Connection to {mx_host}:25 timed out after {SMTP_TIMEOUT}s."
        result["smtp_exists"] = None

    except ConnectionRefusedError:
        result["smtp_status"] = "blocked"
        result["smtp_note"]   = f"Port 25 refused on {mx_host}. Server blocks SMTP verification."
        result["smtp_exists"] = None

    except Exception as e:
        result["smtp_status"] = "unknown"
        result["smtp_note"]   = f"SMTP error: {str(e)[:120]}"
        result["smtp_exists"] = None


# ─────────────────────────────────────────────────────────────
# WHOIS DOMAIN LOOKUP
# ─────────────────────────────────────────────────────────────

def _whois_lookup(domain: str, result: dict) -> None:
    """
    Full WHOIS lookup for domain creation date, registrar, org, etc.
    """
    try:
        import whois
        w = whois.whois(domain)

        # Creation date
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if hasattr(created, "replace"):
                created_clean = created.replace(tzinfo=None)
            else:
                created_clean = created
            result["domain_created"] = str(created)[:10]
            age_days = (datetime.datetime.utcnow() - created_clean).days
            years    = age_days // 365
            months   = (age_days % 365) // 30
            days     = age_days % 30
            if years > 0:
                result["domain_age"] = f"{years} yr {months} mo"
            elif months > 0:
                result["domain_age"] = f"{months} mo {days} days"
            else:
                result["domain_age"] = f"{age_days} days (very new!)"

        # Expiry date
        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        if expires:
            result["domain_expires"] = str(expires)[:10]

        # Updated
        updated = w.updated_date
        if isinstance(updated, list):
            updated = updated[0]
        if updated:
            result["domain_updated"] = str(updated)[:10]

        # Registrar
        result["domain_registrar"] = str(w.registrar or "").strip()

        # Organisation
        org = (w.org or w.registrant_name or
               getattr(w, "registrant_organization", "") or "")
        result["domain_org"] = str(org).strip()

        # Nameservers
        ns = w.name_servers or []
        if isinstance(ns, str):
            ns = [ns]
        result["domain_nameservers"] = [str(n).lower() for n in ns][:6]

        # Status
        status = w.status or []
        if isinstance(status, str):
            status = [status]
        result["domain_status"] = [str(s) for s in status][:4]

    except ImportError:
        result["whois_error"] = "python-whois not installed. Run: pip install python-whois"
    except Exception as e:
        result["whois_error"] = f"WHOIS lookup failed: {str(e)[:120]}"


# ─────────────────────────────────────────────────────────────
# SUMMARY BUILDER
# ─────────────────────────────────────────────────────────────

def _build_summary(r: dict) -> str:
    parts = []

    # SMTP result
    status_map = {
        "exists":      f"✓ Email EXISTS on server (SMTP 250 confirmed)",
        "not_exists":  f"✗ Email does NOT exist (SMTP 550 rejected)",
        "catch_all":   f"⚑ Server uses catch-all — cannot confirm individually",
        "blocked":     f"⚠ SMTP check blocked by server",
        "unknown":     f"? Server gave inconclusive response",
    }
    parts.append(status_map.get(r["smtp_status"], "? Unknown"))

    # Domain age
    if r["domain_created"]:
        parts.append(f"Domain created: {r['domain_created']} ({r['domain_age']} ago)")
    if r["domain_registrar"]:
        parts.append(f"Registrar: {r['domain_registrar']}")

    return " | ".join(parts)


# ─────────────────────────────────────────────────────────────
# CONVENIENCE: verify just the SMTP part
# ─────────────────────────────────────────────────────────────

def check_email_exists(email: str) -> dict:
    """Quick SMTP-only check. Returns exists/not_exists/unknown/blocked."""
    r      = {"email": email, "domain": "", "mx_records": [],
              "mx_found": False, "smtp_exists": None,
              "smtp_status": "unknown", "smtp_code": 0,
              "smtp_message": "", "smtp_server": "", "smtp_note": ""}
    parts  = email.strip().lower().split("@")
    if len(parts) != 2:
        return r
    r["domain"] = parts[1]
    mx_host     = _get_mx_record(parts[1], r)
    if mx_host:
        _smtp_verify(email, mx_host, r)
    return r