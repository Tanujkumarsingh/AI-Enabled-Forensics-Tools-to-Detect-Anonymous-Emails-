# ============================================================
# FILE: src/preprocessing/email_loader.py
# ============================================================
import os
from email import policy
from email.parser import BytesParser, Parser

def load_email(source):
    """Load email from file path, bytes, or string. Returns parsed msg object."""
    if isinstance(source, bytes):
        return BytesParser(policy=policy.default).parsebytes(source)
    if isinstance(source, str) and os.path.isfile(source):
        with open(source, "rb") as f:
            return BytesParser(policy=policy.default).parsebytes(f.read())
    if isinstance(source, str):
        return Parser(policy=policy.default).parsestr(source)
    return None

def load_email_from_path(path: str):
    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as f:
        raw = f.read()
    if ext == ".msg":
        try:
            import extract_msg
            msg_obj = extract_msg.Message(path)
            raw_str = f"From: {msg_obj.sender}\nSubject: {msg_obj.subject}\n\n{msg_obj.body}"
            return Parser(policy=policy.default).parsestr(raw_str)
        except Exception:
            pass
    return BytesParser(policy=policy.default).parsebytes(raw)