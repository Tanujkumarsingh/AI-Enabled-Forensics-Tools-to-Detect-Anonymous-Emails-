# ============================================================
# FILE: src/preprocessing/attachment_extractor.py
# ============================================================
import os
import hashlib

SAVE_DIR = os.path.join("data", "attachments")

def extract_attachments(msg, save: bool = True) -> list:
    """
    Extract all attachments from a parsed email message.
    Returns list of dicts with name, content_type, size_bytes, sha256, saved_path.
    """
    os.makedirs(SAVE_DIR, exist_ok=True)
    results = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            name    = part.get_filename() or "unknown_attachment"
            payload = part.get_payload(decode=True) or b""
            sha256  = hashlib.sha256(payload).hexdigest()
            saved   = ""
            if save and payload:
                safe_name = "".join(c for c in name if c.isalnum() or c in "._- ")
                path = os.path.join(SAVE_DIR, sha256[:8] + "_" + safe_name)
                with open(path, "wb") as f:
                    f.write(payload)
                saved = path
            results.append({
                "name":         name,
                "content_type": part.get_content_type(),
                "size_bytes":   len(payload),
                "sha256":       sha256,
                "saved_path":   saved,
            })
    return results