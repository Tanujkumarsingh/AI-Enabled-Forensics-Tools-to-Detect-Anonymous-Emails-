# ============================================================
# FILE: src/ingestion/dataset_loader.py
# PASTE AS: src/ingestion/dataset_loader.py
# ============================================================
"""
Loads email datasets from CSV or XLSX files.
Normalises column names so the pipeline always gets
subject, sender, body regardless of original column naming.
"""

import os


COLUMN_MAP = {
    "subject":  ["subject", "Subject", "subject_line", "email_subject", "title"],
    "sender":   ["from",    "From",    "sender",        "Sender",        "from_email", "email_from"],
    "body":     ["body",    "Body",    "content",       "Content",       "message",    "text",       "email_body"],
    "label":    ["label",   "Label",   "class",         "target",        "is_phishing","spam"],
}


def load_dataset(file_path: str) -> list:
    """
    Load CSV or XLSX dataset.
    Returns list of dicts with keys: subject, sender, body, label (optional).
    """
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas is required. Run: pip install pandas openpyxl")

    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".csv":
        df = pd.read_csv(file_path)
    elif ext in (".xlsx", ".xls"):
        df = pd.read_excel(file_path)
    else:
        raise ValueError(f"Unsupported dataset format: {ext}")

    # Normalise column names
    col_map = {}
    for target, variants in COLUMN_MAP.items():
        for v in variants:
            if v in df.columns:
                col_map[target] = v
                break

    if "body" not in col_map:
        raise ValueError("Dataset must have a body/content/message column.")

    rows = []
    for _, row in df.iterrows():
        rows.append({
            "subject": str(row.get(col_map.get("subject", ""), "") or ""),
            "sender":  str(row.get(col_map.get("sender",  ""), "") or ""),
            "body":    str(row.get(col_map.get("body",    ""), "") or ""),
            "label":   str(row.get(col_map.get("label",   ""), "") or ""),
        })
    return rows


def load_dataset_from_bytes(file_bytes: bytes, filename: str) -> list:
    """Load dataset directly from uploaded file bytes."""
    import io
    import pandas as pd

    ext = os.path.splitext(filename)[1].lower()
    buf = io.BytesIO(file_bytes)

    if ext == ".csv":
        df = pd.read_csv(buf)
    elif ext in (".xlsx", ".xls"):
        df = pd.read_excel(buf)
    else:
        raise ValueError(f"Unsupported format: {ext}")

    col_map = {}
    for target, variants in COLUMN_MAP.items():
        for v in variants:
            if v in df.columns:
                col_map[target] = v
                break

    rows = []
    for _, row in df.iterrows():
        rows.append({
            "subject": str(row.get(col_map.get("subject", ""), "") or ""),
            "sender":  str(row.get(col_map.get("sender",  ""), "") or ""),
            "body":    str(row.get(col_map.get("body",    ""), "") or ""),
            "label":   str(row.get(col_map.get("label",   ""), "") or ""),
        })
    return rows