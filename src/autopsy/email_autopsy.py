# ============================================================
# FILE: src/autopsy/email_autopsy.py
# PASTE THIS AS: src/autopsy/email_autopsy.py
# ============================================================
"""
Autopsy-style Email Structural Extractor.
Converts any raw email into 30+ structured forensic fields.
Works with .eml, .txt, .msg formats AND manual input.
"""

import re
import hashlib
import datetime
from email import policy
from email.parser import BytesParser, Parser
from typing import Any, Optional


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class EmailAutopsy:
    """
    Breaks every email into labelled forensic columns.
    Entry points:
        autopsy_from_file(path)          ← .eml / .txt file path
        autopsy_from_bytes(bytes)        ← uploaded file bytes
        autopsy_from_string(string)      ← raw email string
        autopsy_from_manual(...)         ← manual UI input
    """

    def __init__(self):
        self.fields = {}

    # ── Entry Points ──────────────────────────────────────────────────────────

    def autopsy_from_file(self, file_path: str) -> dict:
        with open(file_path, "rb") as f:
            raw = f.read()
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        return self._extract_all(msg, raw_bytes=raw)

    def autopsy_from_bytes(self, raw_bytes: bytes) -> dict:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        return self._extract_all(msg, raw_bytes=raw_bytes)

    def autopsy_from_string(self, raw_string: str) -> dict:
        msg = Parser(policy=policy.default).parsestr(raw_string)
        return self._extract_all(msg, raw_bytes=raw_string.encode())

    def autopsy_from_manual(self,
                             subject: str,
                             sender: str,
                             body: str,
                             urls: Optional[list] = None,
                             attachments: Optional[list] = None) -> dict:
        """Build autopsy dict from manually entered data (UI form)."""
        subject     = subject or ""
        sender      = sender  or ""
        body        = body    or ""
        urls        = urls    or []
        attachments = attachments or []

        extracted_urls = self._extract_urls(body) if not urls else urls
        suspicious     = self._flag_suspicious_urls(extracted_urls)

        combo_hash = hashlib.sha256(
            (subject + sender + body).encode("utf-8", errors="replace")
        ).hexdigest()

        return {
            # Identity
            "subject":            subject,
            "sender_email":       self._extract_email_addr(sender),
            "sender_name":        self._extract_name(sender),
            "sender_domain":      self._extract_domain(self._extract_email_addr(sender)),
            "recipient_email":    "",
            "recipient_name":     "",
            "reply_to":           "",
            "return_path":        "",
            # Timing
            "date_sent":          "",
            "timestamp_utc":      "",
            "timezone":           "",
            # Content
            "body_text":          body,
            "body_html":          "",
            "body_length":        len(body),
            "word_count":         len(body.split()),
            "language":           self._detect_language(body),
            # URLs
            "urls_found":         extracted_urls,
            "url_count":          len(extracted_urls),
            "suspicious_urls":    suspicious,
            # Attachments
            "attachments":        attachments,
            "attachment_count":   len(attachments),
            "attachment_names":   [a.get("name", "") for a in attachments],
            "attachment_types":   [a.get("type", "") for a in attachments],
            # Network
            "ip_addresses":       [],
            "received_chain":     [],
            "x_originating_ip":   "",
            "mail_server":        "",
            # Authentication
            "spf_result":         "unknown",
            "dkim_result":        "unknown",
            "dmarc_result":       "unknown",
            "spoof_detected":     False,
            # Security
            "is_anonymous":       False,
            "anonymous_provider": "",
            "is_temp_mail":       self._check_temp_mail(
                                      self._extract_domain(
                                          self._extract_email_addr(sender)
                                      )
                                  ),
            # Hash
            "email_hash_sha256":  combo_hash,
            "attachment_hashes":  [a.get("sha256", "") for a in attachments],
            # Headers
            "raw_headers":        {},
            "message_id":         "",
            "x_mailer":           "",
            "mime_version":       "",
            "content_type":       "",
            # Meta
            "source_type":        "manual",
            "autopsy_timestamp":  datetime.datetime.utcnow().isoformat(),
        }

    # ── Core Extractor ────────────────────────────────────────────────────────

    def _extract_all(self, msg: Any, raw_bytes: bytes) -> dict:
        """Master field extractor for parsed email objects."""

        subject      = str(msg.get("Subject",          "") or "")
        from_raw     = str(msg.get("From",             "") or "")
        to_raw       = str(msg.get("To",               "") or "")
        reply_to     = str(msg.get("Reply-To",         "") or "")
        return_path  = str(msg.get("Return-Path",      "") or "")
        date_raw     = str(msg.get("Date",             "") or "")
        message_id   = str(msg.get("Message-ID",       "") or "")
        x_mailer     = str(msg.get("X-Mailer",         "") or "")
        mime_version = str(msg.get("MIME-Version",     "") or "")
        content_type = str(msg.get("Content-Type",     "") or "")
        x_orig_ip    = str(msg.get("X-Originating-IP", "") or "")

        sender_email    = self._extract_email_addr(from_raw)
        sender_name     = self._extract_name(from_raw)
        sender_domain   = self._extract_domain(sender_email)
        recipient_email = self._extract_email_addr(to_raw)
        recipient_name  = self._extract_name(to_raw)

        _, utc_str, timezone = self._parse_date(date_raw)

        body_text, body_html = self._extract_body(msg)
        all_text             = body_text + " " + body_html
        urls_found           = self._extract_urls(all_text)
        suspicious_urls      = self._flag_suspicious_urls(urls_found)

        attachments    = self._extract_attachments(msg)
        received_chain = self._extract_received_chain(msg)
        ip_list        = self._extract_ips_from_chain(received_chain)

        raw_headers  = {k: str(v) for k, v in msg.items()}
        email_hash   = hashlib.sha256(raw_bytes).hexdigest()

        return {
            # Identity
            "subject":            subject,
            "sender_email":       sender_email,
            "sender_name":        sender_name,
            "sender_domain":      sender_domain,
            "recipient_email":    recipient_email,
            "recipient_name":     recipient_name,
            "reply_to":           reply_to,
            "return_path":        return_path,
            # Timing
            "date_sent":          date_raw,
            "timestamp_utc":      utc_str,
            "timezone":           timezone,
            # Content
            "body_text":          body_text,
            "body_html":          body_html,
            "body_length":        len(body_text),
            "word_count":         len(body_text.split()),
            "language":           self._detect_language(body_text),
            # URLs
            "urls_found":         urls_found,
            "url_count":          len(urls_found),
            "suspicious_urls":    suspicious_urls,
            # Attachments
            "attachments":        attachments,
            "attachment_count":   len(attachments),
            "attachment_names":   [a["name"] for a in attachments],
            "attachment_types":   [a["content_type"] for a in attachments],
            # Network
            "ip_addresses":       ip_list,
            "received_chain":     received_chain,
            "x_originating_ip":   x_orig_ip,
            "mail_server":        received_chain[0] if received_chain else "",
            # Authentication
            "spf_result":         "pending",
            "dkim_result":        "pending",
            "dmarc_result":       "pending",
            "spoof_detected":     False,
            # Security
            "is_anonymous":       False,
            "anonymous_provider": "",
            "is_temp_mail":       self._check_temp_mail(sender_domain),
            # Hash
            "email_hash_sha256":  email_hash,
            "attachment_hashes":  [a.get("sha256", "") for a in attachments],
            # Headers
            "raw_headers":        raw_headers,
            "message_id":         message_id,
            "x_mailer":           x_mailer,
            "mime_version":       mime_version,
            "content_type":       content_type,
            # Meta
            "source_type":        "file",
            "autopsy_timestamp":  datetime.datetime.utcnow().isoformat(),
        }

    # ── Parsing Helpers ───────────────────────────────────────────────────────

    def _extract_email_addr(self, raw: str) -> str:
        match = re.search(r"[\w.+\-]+@[\w.\-]+\.\w+", raw)
        return match.group(0) if match else raw.strip()

    def _extract_name(self, raw: str) -> str:
        match = re.match(r'^(.+?)\s*<', raw)
        if match:
            return match.group(1).strip().strip('"').strip("'")
        return ""

    def _extract_domain(self, email_addr: str) -> str:
        if "@" in email_addr:
            return email_addr.split("@")[-1].lower().strip()
        return ""

    def _extract_body(self, msg) -> tuple:
        body_text = ""
        body_html = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                try:
                    if ct == "text/plain":
                        body_text += part.get_content() or ""
                    elif ct == "text/html":
                        body_html += part.get_content() or ""
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    decoded = payload.decode("utf-8", errors="replace")
                    if ct == "text/plain":
                        body_text += decoded
                    elif ct == "text/html":
                        body_html += decoded
        else:
            try:
                body_text = msg.get_content() or ""
            except Exception:
                payload   = msg.get_payload(decode=True) or b""
                body_text = payload.decode("utf-8", errors="replace")
        return body_text.strip(), body_html.strip()

    def _extract_urls(self, text: str) -> list:
        return list(set(re.findall(r"https?://[^\s<>\"']+", text)))

    def _flag_suspicious_urls(self, urls: list) -> list:
        keywords = [
            "login", "verify", "account", "secure", "update", "confirm",
            "click", "free", "prize", "winner", "bank", "paypal", "urgent",
            "reset", "password", "credential", "validate", "suspend",
        ]
        flagged = []
        for url in urls:
            lower = url.lower()
            if any(kw in lower for kw in keywords):
                flagged.append(url)
            elif re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                flagged.append(url)
        return flagged

    def _extract_attachments(self, msg) -> list:
        result = []
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                name    = part.get_filename() or "unknown_file"
                payload = part.get_payload(decode=True) or b""
                result.append({
                    "name":         name,
                    "content_type": part.get_content_type(),
                    "size_bytes":   len(payload),
                    "sha256":       hashlib.sha256(payload).hexdigest(),
                })
        return result

    def _extract_received_chain(self, msg) -> list:
        received = msg.get_all("Received") or []
        return [str(r).strip() for r in received]

    def _extract_ips_from_chain(self, chain: list) -> list:
        ips = []
        for header in chain:
            ips.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", header))
        public = [ip for ip in ips if not self._is_private_ip(ip)]
        return list(dict.fromkeys(public))  # dedup, preserve order

    def _is_private_ip(self, ip: str) -> bool:
        return bool(re.match(
            r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)", ip
        ))

    def _parse_date(self, date_str: str) -> tuple:
        try:
            from email.utils import parsedate_to_datetime
            dt      = parsedate_to_datetime(date_str)
            utc_t   = dt.utctimetuple()
            utc_str = datetime.datetime(*utc_t[:6]).isoformat() + "Z"
            tz      = str(dt.tzinfo) if dt.tzinfo else "UTC"
            return dt, utc_str, tz
        except Exception:
            return None, "", "Unknown"

    def _detect_language(self, text: str) -> str:
        if not text.strip():
            return "unknown"
        try:
            from langdetect import detect
            return detect(text)
        except Exception:
            return "en"

    def _check_temp_mail(self, domain: str) -> bool:
        TEMP_DOMAINS = {
            "mailinator.com", "guerrillamail.com", "10minutemail.com",
            "tempmail.com", "throwaway.email", "yopmail.com",
            "sharklasers.com", "trashmail.com", "dispostable.com",
            "maildrop.cc", "fakeinbox.com", "spamgourmet.com",
            "spamgourmet.net", "mailnull.com", "trashmail.me",
        }
        return domain.lower() in TEMP_DOMAINS


# ─────────────────────────────────────────────────────────────────────────────
# FLAT FORMATTER — for CSV / DataFrame export
# ─────────────────────────────────────────────────────────────────────────────

def format_for_dataframe(fields: dict) -> dict:
    """Converts the full autopsy dict into a flat CSV-ready row."""
    return {
        "Subject":             fields.get("subject",            ""),
        "Sender Email":        fields.get("sender_email",       ""),
        "Sender Name":         fields.get("sender_name",        ""),
        "Sender Domain":       fields.get("sender_domain",      ""),
        "Recipient Email":     fields.get("recipient_email",    ""),
        "Reply-To":            fields.get("reply_to",           ""),
        "Return-Path":         fields.get("return_path",        ""),
        "Date Sent":           fields.get("date_sent",          ""),
        "Timestamp UTC":       fields.get("timestamp_utc",      ""),
        "Timezone":            fields.get("timezone",           ""),
        "Body Length":         fields.get("body_length",        0),
        "Word Count":          fields.get("word_count",         0),
        "Language":            fields.get("language",           ""),
        "URL Count":           fields.get("url_count",          0),
        "URLs":                "; ".join(fields.get("urls_found",       [])),
        "Suspicious URLs":     "; ".join(fields.get("suspicious_urls",  [])),
        "Attachment Count":    fields.get("attachment_count",   0),
        "Attachment Names":    "; ".join(fields.get("attachment_names", [])),
        "Attachment Types":    "; ".join(fields.get("attachment_types", [])),
        "IP Addresses":        "; ".join(fields.get("ip_addresses",     [])),
        "X-Originating-IP":    fields.get("x_originating_ip",  ""),
        "Mail Server":         fields.get("mail_server",        ""),
        "SPF Result":          fields.get("spf_result",         ""),
        "DKIM Result":         fields.get("dkim_result",        ""),
        "DMARC Result":        fields.get("dmarc_result",       ""),
        "Spoof Detected":      fields.get("spoof_detected",     False),
        "Is Anonymous":        fields.get("is_anonymous",       False),
        "Anonymous Provider":  fields.get("anonymous_provider", ""),
        "Is Temp Mail":        fields.get("is_temp_mail",       False),
        "Email Hash SHA256":   fields.get("email_hash_sha256",  ""),
        "Message-ID":          fields.get("message_id",         ""),
        "X-Mailer":            fields.get("x_mailer",           ""),
        "Source Type":         fields.get("source_type",        ""),
        "Autopsy Timestamp":   fields.get("autopsy_timestamp",  ""),
    }