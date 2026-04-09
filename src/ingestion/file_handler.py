# ============================================================
# FILE: src/ingestion/file_handler.py
# PASTE AS: src/ingestion/file_handler.py
# ============================================================
"""
Handles uploaded email files: validates extension, saves to data/raw/,
and returns parsed content via EmailAutopsy.
"""

import os
import uuid

UPLOAD_DIR     = os.path.join("data", "raw")
ALLOWED_EXTS   = {".eml", ".txt", ".msg"}


def handle_uploaded_file(file_bytes: bytes, filename: str) -> dict:
    """
    Save uploaded file and run autopsy.
    Returns autopsy fields dict.
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTS:
        raise ValueError(f"Unsupported file type: {ext}. Allowed: {', '.join(ALLOWED_EXTS)}")

    # Save raw file
    safe_name  = uuid.uuid4().hex[:8] + "_" + os.path.basename(filename)
    saved_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(saved_path, "wb") as f:
        f.write(file_bytes)

    # Parse
    from src.autopsy.email_autopsy import EmailAutopsy
    autopsy = EmailAutopsy()
    if ext == ".msg":
        fields = autopsy.autopsy_from_file(saved_path)
    else:
        fields = autopsy.autopsy_from_bytes(file_bytes)

    fields["saved_path"]  = saved_path
    fields["source_type"] = "file"
    return fields


def validate_extension(filename: str) -> bool:
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTS