# ============================================================
# FILE: src/forensic/metadata_analyzer.py
# ============================================================
import datetime

def analyze_metadata(msg) -> dict:
    """Extract and analyze email metadata from headers."""
    return {
        "message_id":    str(msg.get("Message-ID", "") or ""),
        "x_mailer":      str(msg.get("X-Mailer", "") or ""),
        "mime_version":  str(msg.get("MIME-Version", "") or ""),
        "content_type":  str(msg.get("Content-Type", "") or ""),
        "x_orig_ip":     str(msg.get("X-Originating-IP", "") or ""),
        "date_raw":      str(msg.get("Date", "") or ""),
        "user_agent":    str(msg.get("User-Agent", "") or ""),
        "thread_topic":  str(msg.get("Thread-Topic", "") or ""),
        "x_priority":    str(msg.get("X-Priority", "") or ""),
        "x_spam_status": str(msg.get("X-Spam-Status", "") or ""),
        "x_spam_score":  str(msg.get("X-Spam-Score", "") or ""),
        "dkim_signature":str(msg.get("DKIM-Signature", "") or ""),
        "received_spf":  str(msg.get("Received-SPF", "") or ""),
        "authentication_results": str(msg.get("Authentication-Results", "") or ""),
        "analyzed_at":   datetime.datetime.utcnow().isoformat(),
    }