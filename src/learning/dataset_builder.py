"""
============================================================
FILE: src/learning/dataset_builder.py
PASTE AS: src/learning/dataset_builder.py

Builds and merges the training datasets for both ML models.

DATASETS USED:
─────────────────────────────────────────────────────────
AI vs Human model:
  1. Enron Email Dataset  — real human work emails (ham)
     Source: https://www.cs.cmu.edu/~enron/
     Download: kaggle datasets download -d wcukierski/enron-email-dataset
     label = 0 (human)

  2. SpamAssassin Dataset — spam + ham emails
     Source: https://spamassassin.apache.org/old/publiccorpus/
     Ham subset is clean human email → label = 0 (human)
     Spam subset is mass/AI-template email → label = 1 (AI)

  3. HC3 Dataset — Human vs ChatGPT answers
     Source: https://huggingface.co/datasets/Hello-SimpleAI/HC3
     human answers → label = 0 (human)
     chatgpt answers → label = 1 (AI)

Safe vs Unsafe model:
  4. Kaggle Phishing Email Dataset
     Source: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
     label = 1 (phishing / unsafe), 0 (legitimate / safe)

  5. CEAS 2008 Spam Dataset
     Source: http://www.ceas.cc/2008/
     spam = unsafe(1), ham = safe(0)

Output CSVs written to:
  datasets/ai_human_training.csv   — for AI vs Human model
  datasets/safe_unsafe_training.csv — for Safe vs Unsafe model
============================================================
"""

import os
import re
import json
import hashlib
import logging
import email as email_lib
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Optional


import pandas as pd

log = logging.getLogger("forensiq.dataset_builder")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR        = Path(__file__).resolve().parents[3]          # project root
DATASETS_DIR    = BASE_DIR / "datasets"
RAW_DIR         = DATASETS_DIR / "raw"
AI_HUMAN_CSV    = DATASETS_DIR / "ai_human_training.csv"
SAFE_UNSAFE_CSV = DATASETS_DIR / "safe_unsafe_training.csv"

DATASETS_DIR.mkdir(exist_ok=True)
RAW_DIR.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# COLUMN SCHEMA
# Both CSVs share this exact schema so the training scripts need no changes.
# ══════════════════════════════════════════════════════════════════════════════

AI_HUMAN_COLS    = ["subject", "body", "sender", "label",  "source", "email_hash"]
SAFE_UNSAFE_COLS = ["subject", "body", "sender", "label",  "source", "email_hash"]
# label meanings:
#   ai_human    → 0=human, 1=AI/machine
#   safe_unsafe → 0=safe/legitimate, 1=unsafe/phishing


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _clean_body(text: str) -> str:
    """Strip excessive whitespace and null bytes."""
    if not text:
        return ""
    text = re.sub(r"\x00", " ", text)
    text = re.sub(r"\r\n|\r", "\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()[:8000]      # cap at 8k chars to keep CSV manageable


def _parse_eml_bytes(raw: bytes) -> dict:
    """Parse raw .eml bytes → {subject, body, sender}."""
    try:
        msg     = BytesParser(policy=policy.default).parsebytes(raw)
        subject = str(msg.get("Subject", ""))
        sender  = str(msg.get("From",    ""))
        body    = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body += part.get_content() or ""
                    except Exception:
                        body += str(part.get_payload(decode=True) or b"",
                                   "utf-8", errors="replace")
        else:
            try:
                body = msg.get_content() or ""
            except Exception:
                body = str(msg.get_payload(decode=True) or b"",
                           "utf-8", errors="replace")
        return {"subject": subject, "body": _clean_body(body), "sender": sender}
    except Exception:
        return {"subject": "", "body": "", "sender": ""}


# ══════════════════════════════════════════════════════════════════════════════
# LOADERS — one function per dataset
# ══════════════════════════════════════════════════════════════════════════════

def load_enron(enron_csv_path: str) -> pd.DataFrame:
    """
    Load the Enron email dataset.

    Expected: Kaggle version with columns [file, message].
    The 'message' column contains the raw .eml text.

    Download:
        kaggle datasets download -d wcukierski/enron-email-dataset
        # or manually from https://www.cs.cmu.edu/~enron/
    """
    path = Path(enron_csv_path)
    if not path.exists():
        log.warning("Enron dataset not found at %s — skipping", enron_csv_path)
        return pd.DataFrame(columns=AI_HUMAN_COLS)

    log.info("Loading Enron dataset from %s ...", enron_csv_path)
    df = pd.read_csv(path, usecols=["message"])

    rows = []
    for _, row in df.iterrows():
        raw = str(row.get("message", "")).encode("utf-8", errors="replace")
        parsed = _parse_eml_bytes(raw)
        if not parsed["body"].strip():
            continue
        rows.append({
            "subject": parsed["subject"],
            "body":    parsed["body"],
            "sender":  parsed["sender"],
            "label":   0,                   # human
            "source":  "enron",
            "email_hash": _hash(parsed["body"]),
        })

    log.info("Enron: loaded %d emails", len(rows))
    return pd.DataFrame(rows, columns=AI_HUMAN_COLS)


def load_spamassassin(spam_dir: str) -> pd.DataFrame:
    """
    Load SpamAssassin public corpus.

    Expected directory structure:
        spam_dir/
            easy_ham/        ← human emails  (label=0)
            hard_ham/        ← human emails  (label=0)
            spam/            ← spam emails   (label=1)
            spam_2/          ← more spam     (label=1)

    Download:
        wget https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
        wget https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2
        (extract into spam_dir/)
    """
    base = Path(spam_dir)
    if not base.exists():
        log.warning("SpamAssassin dir not found at %s — skipping", spam_dir)
        return pd.DataFrame(columns=AI_HUMAN_COLS)

    FOLDER_LABELS = {
        "easy_ham": 0, "hard_ham": 0,
        "spam":     1, "spam_2":   1,
    }
    rows = []

    for folder, label in FOLDER_LABELS.items():
        folder_path = base / folder
        if not folder_path.exists():
            continue
        for fpath in list(folder_path.iterdir())[:5000]:   # cap per folder
            try:
                raw    = fpath.read_bytes()
                parsed = _parse_eml_bytes(raw)
                if not parsed["body"].strip():
                    continue
                rows.append({
                    "subject": parsed["subject"],
                    "body":    parsed["body"],
                    "sender":  parsed["sender"],
                    "label":   label,
                    "source":  f"spamassassin_{folder}",
                    "email_hash": _hash(parsed["body"]),
                })
            except Exception:
                continue

    log.info("SpamAssassin: loaded %d emails", len(rows))
    return pd.DataFrame(rows, columns=AI_HUMAN_COLS)


def load_hc3(hc3_jsonl_path: str) -> pd.DataFrame:
    """
    Load HC3 (Human ChatGPT Comparison Corpus).

    Source: https://huggingface.co/datasets/Hello-SimpleAI/HC3
    Download as JSONL:
        from datasets import load_dataset
        ds = load_dataset("Hello-SimpleAI/HC3", "all")
        ds["train"].to_json("datasets/raw/hc3_train.jsonl")

    JSONL format: {"question": "...", "human_answers": [...], "chatgpt_answers": [...]}
    We treat question+human_answer as body (label=0) and
    question+chatgpt_answer as body (label=1).
    """
    path = Path(hc3_jsonl_path)
    if not path.exists():
        log.warning("HC3 dataset not found at %s — skipping", hc3_jsonl_path)
        return pd.DataFrame(columns=AI_HUMAN_COLS)

    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                obj      = json.loads(line.strip())
                question = obj.get("question", "")
                for ans in obj.get("human_answers", []):
                    body = _clean_body(f"{question}\n{ans}")
                    if body:
                        rows.append({
                            "subject": question[:100],
                            "body":    body,
                            "sender":  "",
                            "label":   0,
                            "source":  "hc3_human",
                            "email_hash": _hash(body),
                        })
                for ans in obj.get("chatgpt_answers", []):
                    body = _clean_body(f"{question}\n{ans}")
                    if body:
                        rows.append({
                            "subject": question[:100],
                            "body":    body,
                            "sender":  "",
                            "label":   1,
                            "source":  "hc3_chatgpt",
                            "email_hash": _hash(body),
                        })
            except Exception:
                continue

    log.info("HC3: loaded %d samples", len(rows))
    return pd.DataFrame(rows, columns=AI_HUMAN_COLS)


def load_kaggle_phishing(phishing_csv_path: str) -> pd.DataFrame:
    """
    Load Kaggle phishing email dataset for Safe vs Unsafe model.

    Supported datasets:
      1. https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
         Columns: label, subject, body, sender (label: 1=phishing, 0=legit)

      2. https://www.kaggle.com/datasets/subhajournal/phishingemails
         Columns: Email Type, Email Text
         Email Type: "Phishing Email"=1, "Safe Email"=0

    We auto-detect which format it is.
    """
    path = Path(phishing_csv_path)
    if not path.exists():
        log.warning("Phishing dataset not found at %s — skipping", phishing_csv_path)
        return pd.DataFrame(columns=SAFE_UNSAFE_COLS)

    log.info("Loading phishing dataset from %s ...", phishing_csv_path)
    df = pd.read_csv(path)
    cols_lower = [c.lower() for c in df.columns]
    rows = []

    # ── Format A: label + subject + body ─────────────────────────────────────
    if "label" in cols_lower or "is_phishing" in cols_lower:
        label_col   = next(c for c in df.columns if c.lower() in ("label", "is_phishing"))
        body_col    = next((c for c in df.columns if c.lower() in ("body", "text", "message", "content")), None)
        subject_col = next((c for c in df.columns if c.lower() == "subject"), None)
        sender_col  = next((c for c in df.columns if c.lower() in ("from", "sender")), None)

        if body_col:
            for _, row in df.iterrows():
                body = _clean_body(str(row.get(body_col, "")))
                subj = str(row.get(subject_col, "")) if subject_col else ""
                sndr = str(row.get(sender_col,  "")) if sender_col  else ""
                lbl  = int(row[label_col]) if str(row[label_col]).isdigit() else \
                       (1 if str(row[label_col]).lower() in ("phishing","spam","1") else 0)
                if body:
                    rows.append({
                        "subject": subj,
                        "body":    body,
                        "sender":  sndr,
                        "label":   lbl,
                        "source":  "kaggle_phishing",
                        "email_hash": _hash(body),
                    })

    # ── Format B: Email Type + Email Text ────────────────────────────────────
    elif "email type" in cols_lower and "email text" in cols_lower:
        type_col = next(c for c in df.columns if c.lower() == "email type")
        text_col = next(c for c in df.columns if c.lower() == "email text")
        for _, row in df.iterrows():
            body = _clean_body(str(row.get(text_col, "")))
            lbl  = 1 if "phishing" in str(row.get(type_col, "")).lower() else 0
            if body:
                rows.append({
                    "subject": "",
                    "body":    body,
                    "sender":  "",
                    "label":   lbl,
                    "source":  "kaggle_phishing_b",
                    "email_hash": _hash(body),
                })

    log.info("Kaggle phishing: loaded %d emails", len(rows))
    return pd.DataFrame(rows, columns=SAFE_UNSAFE_COLS)


def load_ceas(ceas_csv_path: str) -> pd.DataFrame:
    """
    Load CEAS 2008 spam/ham dataset for Safe vs Unsafe model.
    Source: http://www.ceas.cc/2008/
    Expected columns: label (1=spam, 0=ham), subject, body
    """
    path = Path(ceas_csv_path)
    if not path.exists():
        log.warning("CEAS dataset not found at %s — skipping", ceas_csv_path)
        return pd.DataFrame(columns=SAFE_UNSAFE_COLS)

    df   = pd.read_csv(path)
    rows = []
    for _, row in df.iterrows():
        body = _clean_body(str(row.get("body", row.get("text", row.get("message", "")))))
        if not body:
            continue
        rows.append({
            "subject": str(row.get("subject", "")),
            "body":    body,
            "sender":  str(row.get("sender", row.get("from", ""))),
            "label":   int(row.get("label", row.get("class", 0))),
            "source":  "ceas2008",
            "email_hash": _hash(body),
        })

    log.info("CEAS 2008: loaded %d emails", len(rows))
    return pd.DataFrame(rows, columns=SAFE_UNSAFE_COLS)


# ══════════════════════════════════════════════════════════════════════════════
# MERGE + DEDUPLICATE + SAVE
# ══════════════════════════════════════════════════════════════════════════════

def _merge_and_save(frames: list, output_path: Path, cols: list) -> pd.DataFrame:
    """Merge multiple dataframes, deduplicate by email_hash, save CSV."""
    # Filter out empty frames
    non_empty = [f for f in frames if not f.empty]
    if not non_empty:
        log.warning("No data to merge for %s", output_path)
        return pd.DataFrame(columns=cols)

    merged = pd.concat(non_empty, ignore_index=True)

    # Deduplicate by email_hash — same email from multiple sources kept once
    before = len(merged)
    merged = merged.drop_duplicates(subset=["email_hash"])
    after  = len(merged)
    log.info("%s → %d rows (%d duplicates removed)", output_path.name, after, before - after)

    # Balance classes — cap majority class at 2× minority to avoid imbalance
    counts    = merged["label"].value_counts()
    min_count = counts.min()
    max_keep  = min_count * 2
    balanced_parts = []
    for lbl, cnt in counts.items():
        part = merged[merged["label"] == lbl]
        if cnt > max_keep:
            part = part.sample(n=max_keep, random_state=42)
        balanced_parts.append(part)
    merged = pd.concat(balanced_parts).sample(frac=1, random_state=42)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(output_path, index=False)
    log.info("Saved %d rows to %s", len(merged), output_path)
    return merged


def build_ai_human_dataset(
    enron_csv:        Optional[str] = None,
    spamassassin_dir: Optional[str] = None,
    hc3_jsonl:        Optional[str] = None,
) -> pd.DataFrame:
    """
    Build the AI vs Human training dataset by merging all three sources.
    Any missing source is skipped gracefully.
    Returns the merged DataFrame and saves it to datasets/ai_human_training.csv
    """
    frames = []
    if enron_csv:
        frames.append(load_enron(enron_csv))
    if spamassassin_dir:
        frames.append(load_spamassassin(spamassassin_dir))
    if hc3_jsonl:
        frames.append(load_hc3(hc3_jsonl))

    # Load existing CSV if it exists (contains previously grown data)
    if AI_HUMAN_CSV.exists():
        existing = pd.read_csv(AI_HUMAN_CSV)
        frames.append(existing)
        log.info("Loaded existing AI/Human dataset: %d rows", len(existing))

    return _merge_and_save(frames, AI_HUMAN_CSV, AI_HUMAN_COLS)


def build_safe_unsafe_dataset(
    phishing_csv: Optional[str] = None,
    ceas_csv:     Optional[str] = None,
) -> pd.DataFrame:
    """
    Build the Safe vs Unsafe training dataset.
    Returns the merged DataFrame and saves it to datasets/safe_unsafe_training.csv
    """
    frames = []
    if phishing_csv:
        frames.append(load_kaggle_phishing(phishing_csv))
    if ceas_csv:
        frames.append(load_ceas(ceas_csv))

    # Load existing CSV
    if SAFE_UNSAFE_CSV.exists():
        existing = pd.read_csv(SAFE_UNSAFE_CSV)
        frames.append(existing)
        log.info("Loaded existing Safe/Unsafe dataset: %d rows", len(existing))

    return _merge_and_save(frames, SAFE_UNSAFE_CSV, SAFE_UNSAFE_COLS)


# ══════════════════════════════════════════════════════════════════════════════
# CLI — run directly to build datasets
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Build ForensIQ training datasets")
    parser.add_argument("--enron",        help="Path to Enron emails.csv")
    parser.add_argument("--spamassassin", help="Path to SpamAssassin directory")
    parser.add_argument("--hc3",          help="Path to HC3 JSONL file")
    parser.add_argument("--phishing",     help="Path to Kaggle phishing CSV")
    parser.add_argument("--ceas",         help="Path to CEAS 2008 CSV")
    args = parser.parse_args()

    print("\n── Building AI vs Human dataset ──────────────────────────")
    df_ah = build_ai_human_dataset(args.enron, args.spamassassin, args.hc3)
    if not df_ah.empty:
        print(f"   Total: {len(df_ah)}  |  Human: {(df_ah.label==0).sum()}  "
              f"|  AI: {(df_ah.label==1).sum()}")

    print("\n── Building Safe vs Unsafe dataset ───────────────────────")
    df_su = build_safe_unsafe_dataset(args.phishing, args.ceas)
    if not df_su.empty:
        print(f"   Total: {len(df_su)}  |  Safe: {(df_su.label==0).sum()}  "
              f"|  Unsafe: {(df_su.label==1).sum()}")

    print("\nDone. Datasets saved to datasets/ folder.")