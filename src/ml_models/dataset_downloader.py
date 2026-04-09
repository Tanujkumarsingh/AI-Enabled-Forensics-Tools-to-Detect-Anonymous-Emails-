"""
src/ml_models/dataset_downloader.py
=====================================
Reads your exact dataset files — no external downloads needed.

YOUR ZIP STRUCTURE:
  human-llm.zip
    └── human-llm/                   ← outer wrapper folder (auto-handled)
          ├── human-generated/
          │     ├── legit.csv         → AI vs Human label=0  (Human)
          │     └── phising.csv       → AI vs Human label=0  (Human)
          └── llm-generated/
                ├── legit.csv (or legit.scv — typo handled)
                │                     → AI vs Human label=1  (AI)
                └── phising.csv       → AI vs Human label=1  (AI)

YOUR PHISHING FILES:
  datasets/raw/phishing/spamassasin.csv     → safe=0
  datasets/raw/phishing/phishing_email.csv  → unsafe=1

YOUR PROJECT ROOT: AI-Email-Forensics/
  (this script lives at: AI-Email-Forensics/src/ml_models/dataset_downloader.py)

LABEL RULES:
  AI vs Human model:
    human-generated/* → label=0  (label = folder, not CSV column)
    llm-generated/*   → label=1  (label = folder, not CSV column)

  Safe vs Unsafe model:
    spamassasin.csv          → safe=0   (forced)
    phishing_email.csv       → unsafe=1 (forced or column-detected)
    human-generated/legit    → safe=0   (bonus safe examples)
    human-generated/phising  → unsafe=1 (bonus unsafe examples)

USAGE:
  python src/ml_models/dataset_downloader.py --all
  python src/ml_models/train_ai_human.py
  python src/ml_models/train_safe_unsafe.py
  python run.py

OUTPUTS:
  datasets/processed/ai_human_training.csv
  datasets/processed/safe_unsafe_training.csv
"""

import os, sys, zipfile, logging
from pathlib import Path

log = logging.getLogger("forensiq.downloader")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ── Project root = AI-Email-Forensics/ ───────────────────────────────────────
# This file is at: AI-Email-Forensics/src/ml_models/dataset_downloader.py
# .parent       = AI-Email-Forensics/src/ml_models/
# .parent.parent = AI-Email-Forensics/src/
# .parent.parent.parent = AI-Email-Forensics/     ← project root ✓
BASE_DIR   = Path(__file__).resolve().parent.parent.parent
RAW_DIR    = BASE_DIR / "datasets" / "raw"
PROC_DIR   = BASE_DIR / "datasets" / "processed"
GROW_DIR   = BASE_DIR / "datasets" / "growth"
MODELS_DIR = BASE_DIR / "models"

for d in [RAW_DIR, PROC_DIR, GROW_DIR, MODELS_DIR,
          RAW_DIR / "ai_vs_human", RAW_DIR / "phishing"]:
    d.mkdir(parents=True, exist_ok=True)

# ── Exact file paths ──────────────────────────────────────────────────────────
AI_HUMAN_ZIP    = RAW_DIR / "ai_vs_human" / "human-llm.zip"
PHISHING_CSV    = RAW_DIR / "phishing"    / "phishing_email.csv"
SPAMASSASIN_CSV = RAW_DIR / "phishing"    / "spamassasin.csv"
EXTRACT_DIR     = RAW_DIR / "ai_vs_human" / "extracted"


# ─────────────────────────────────────────────────────────────────────────────
# ZIP EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_extracted() -> bool:
    """
    Extract human-llm.zip to EXTRACT_DIR.
    Handles the case where the ZIP contains an outer wrapper folder
    (e.g. extracts to extracted/human-llm/ instead of extracted/ directly).
    Returns True on success.
    """
    if not AI_HUMAN_ZIP.exists():
        log.error(
            "human-llm.zip NOT FOUND at: %s\n"
            "Make sure it is at: datasets/raw/ai_vs_human/human-llm.zip", AI_HUMAN_ZIP)
        return False

    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

    # Check if already extracted — look anywhere inside extracted/
    existing = _find_folder_recursive(EXTRACT_DIR, ["human-generated", "human generated"])
    if existing:
        log.info("Already extracted — found: %s", existing)
        return True

    log.info("Extracting %s ...", AI_HUMAN_ZIP.name)
    try:
        with zipfile.ZipFile(AI_HUMAN_ZIP, "r") as zf:
            zf.extractall(EXTRACT_DIR)
        log.info("Extraction complete. Contents:")
        for item in sorted(EXTRACT_DIR.rglob("*")):
            if item.is_file():
                log.info("  %s", item.relative_to(EXTRACT_DIR))
        return True
    except zipfile.BadZipFile:
        log.error("human-llm.zip is corrupted or not a valid ZIP file.")
        return False
    except Exception as e:
        log.error("ZIP extraction failed: %s", e)
        return False


def _find_folder_recursive(root: Path, name_keywords: list) -> Path | None:
    """
    Search the entire tree under root for a directory whose name contains
    any of the keywords (case-insensitive).
    Returns the Path if found, else None.
    """
    if not root.exists():
        return None
    for d in root.rglob("*"):
        if d.is_dir():
            name_lower = d.name.lower().replace("-", " ").replace("_", " ")
            if any(kw.lower() in name_lower for kw in name_keywords):
                return d
    return None


def _find_csv_in_folder(folder: Path, name_keywords: list) -> Path | None:
    """
    Find a CSV (or .scv typo) in folder whose stem contains any keyword.
    Falls back to first .csv if no name match.
    """
    if not folder or not folder.exists():
        return None
    # Support .scv typo (e.g. legit.scv)
    all_csv = list(folder.glob("*.csv")) + list(folder.glob("*.scv"))
    for f in sorted(all_csv):
        if any(kw.lower() in f.stem.lower() for kw in name_keywords):
            return f
    return all_csv[0] if all_csv else None


# ─────────────────────────────────────────────────────────────────────────────
# CSV READING
# ─────────────────────────────────────────────────────────────────────────────

def _read_csv(path: Path):
    """Read CSV or .scv file, try UTF-8 then latin-1."""
    try:
        import pandas as pd
        # .scv files are still comma-separated — just a typo in the extension
        return pd.read_csv(path, encoding="utf-8", on_bad_lines="skip")
    except Exception:
        try:
            import pandas as pd
            return pd.read_csv(path, encoding="latin-1", on_bad_lines="skip")
        except Exception as e:
            log.error("Cannot read %s: %s", path.name, e)
            return None


def _find_body_col(df) -> str | None:
    """Return the best body/text column from a DataFrame."""
    cl = {c.lower().strip(): c for c in df.columns}
    match = next((cl[k] for k in (
        "body", "text", "email", "content", "message",
        "email_text", "email text", "email body", "mail",
        "input", "email content", "description", "v2",
        "email_content", "emailcontent",
    ) if k in cl), None)
    if match:
        return match
    # Fallback: string column with longest average content
    str_cols = [c for c in df.columns if df[c].dtype == object]
    if str_cols:
        return max(str_cols, key=lambda c: df[c].str.len().mean() or 0)
    return None


def _find_subject_col(df) -> str | None:
    cl = {c.lower().strip(): c for c in df.columns}
    return next((cl[k] for k in (
        "subject", "title", "subject line", "header", "email subject"
    ) if k in cl), None)


def _find_label_col(df) -> str | None:
    cl = {c.lower().strip(): c for c in df.columns}
    return next((cl[k] for k in (
        "label", "class", "target", "generated", "is_ai",
        "email type", "type", "spam", "is_phishing",
        "category", "is_spam", "output", "classification"
    ) if k in cl), None)


def _norm_su_label(val: str) -> int:
    """Normalise safe/unsafe label. Returns -1 if unrecognised."""
    v = val.strip().lower()
    if v in ("0","safe","ham","legit","legitimate","not phishing",
             "benign","safe email","false","no"):
        return 0
    if v in ("1","unsafe","spam","phishing","malicious","fraud",
             "scam","phishing email","true","yes","1.0"):
        return 1
    if any(k in v for k in ("phishing","spam","malicious","scam","fraud")):
        return 1
    if any(k in v for k in ("safe","ham","legit","benign")):
        return 0
    try:
        return 1 if float(v) >= 0.5 else 0
    except Exception:
        return -1


# ─────────────────────────────────────────────────────────────────────────────
# ROW EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def _extract_rows_forced(df, forced_label: int, source: str) -> list:
    """
    Extract rows from df, forcing ALL rows to forced_label.
    Used for AI vs Human dataset where label comes from folder, not CSV column.
    """
    rows = []
    if df is None or df.empty:
        return rows
    bc = _find_body_col(df)
    sc = _find_subject_col(df)
    if not bc:
        log.warning("  [%s] No body column found. Columns: %s", source, list(df.columns))
        return rows
    log.info("  [%s] body='%s' subject='%s' rows=%d → forced label=%d",
             source, bc, sc or "—", len(df), forced_label)
    for _, row in df.iterrows():
        body    = str(row.get(bc, "") or "").strip()
        subject = str(row.get(sc, "") or "").strip()[:200] if sc else ""
        if len(body) > 10:
            rows.append({
                "subject": subject,
                "body":    body[:4000],
                "label":   forced_label,
                "source":  source,
            })
    log.info("  [%s] → %d rows extracted", source, len(rows))
    return rows


def _extract_rows_with_label(df, source: str,
                              safe_fallback: bool = False,
                              phishing_fallback: bool = False) -> list:
    """
    Extract rows from df, detecting label column if possible.
    Falls back to forced label if no label column found.
    Used for spamassasin.csv and phishing_email.csv.
    """
    rows = []
    if df is None or df.empty:
        return rows
    bc = _find_body_col(df)
    sc = _find_subject_col(df)
    lc = _find_label_col(df)
    if not bc:
        log.warning("  [%s] No body column found. Columns: %s", source, list(df.columns))
        return rows
    log.info("  [%s] body='%s' subject='%s' label_col='%s' rows=%d",
             source, bc, sc or "—", lc or "NONE (forced)", len(df))
    for _, row in df.iterrows():
        body    = str(row.get(bc, "") or "").strip()
        subject = str(row.get(sc, "") or "").strip()[:200] if sc else ""
        if len(body) <= 10:
            continue
        if lc:
            lbl = _norm_su_label(str(row.get(lc, "")))
            if lbl == -1:
                continue
        elif safe_fallback:
            lbl = 0
        elif phishing_fallback:
            lbl = 1
        else:
            continue
        rows.append({
            "subject": subject,
            "body":    body[:4000],
            "label":   lbl,
            "source":  source,
        })
    safe_n   = sum(1 for r in rows if r["label"] == 0)
    unsafe_n = sum(1 for r in rows if r["label"] == 1)
    log.info("  [%s] → %d rows (safe=%d, unsafe=%d)", source, len(rows), safe_n, unsafe_n)
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# BUILD AI vs HUMAN TRAINING CSV
# ─────────────────────────────────────────────────────────────────────────────

def build_ai_human_csv() -> str:
    """
    Reads from human-llm.zip:
      human-generated/legit.csv   → label=0 (Human)
      human-generated/phising.csv → label=0 (Human)
      llm-generated/legit.csv     → label=1 (AI)   [also handles legit.scv typo]
      llm-generated/phising.csv   → label=1 (AI)

    Label is determined by FOLDER NAME, not any CSV column.
    The ZIP may have an outer wrapper folder — this is handled automatically.
    """
    try:
        import pandas as pd
    except ImportError:
        log.error("pip install pandas"); return ""

    log.info("=== Building AI vs Human training dataset ===")

    if not _ensure_extracted():
        return ""

    rows = []

    # ── human-generated/ → label=0 (Human) ────────────────────────────────
    human_dir = _find_folder_recursive(EXTRACT_DIR, ["human-generated", "human generated"])
    if not human_dir:
        log.error(
            "Could not find 'human-generated' folder anywhere under: %s\n"
            "Please check your ZIP structure.", EXTRACT_DIR)
        log.info("Entire extracted tree:")
        for p in sorted(EXTRACT_DIR.rglob("*")):
            log.info("  %s", p.relative_to(EXTRACT_DIR))
    else:
        log.info("Found human-generated at: %s", human_dir)

        legit_f = _find_csv_in_folder(human_dir, ["legit"])
        if legit_f:
            df = _read_csv(legit_f)
            rows.extend(_extract_rows_forced(df, 0, "human_legit"))
        else:
            log.warning("  legit.csv not found in %s — files: %s",
                        human_dir.name,
                        [f.name for f in sorted(human_dir.iterdir())])

        phish_f = _find_csv_in_folder(human_dir, ["phising", "phishing"])
        if phish_f:
            df = _read_csv(phish_f)
            rows.extend(_extract_rows_forced(df, 0, "human_phising"))
        else:
            log.warning("  phising.csv not found in %s — files: %s",
                        human_dir.name,
                        [f.name for f in sorted(human_dir.iterdir())])

    # ── llm-generated/ → label=1 (AI) ─────────────────────────────────────
    llm_dir = _find_folder_recursive(EXTRACT_DIR, ["llm-generated", "llm generated"])
    if not llm_dir:
        log.error(
            "Could not find 'llm-generated' folder anywhere under: %s", EXTRACT_DIR)
    else:
        log.info("Found llm-generated at: %s", llm_dir)

        # handles both legit.csv and legit.scv (typo in your path)
        legit_f = _find_csv_in_folder(llm_dir, ["legit"])
        if legit_f:
            df = _read_csv(legit_f)
            rows.extend(_extract_rows_forced(df, 1, "llm_legit"))
        else:
            log.warning("  legit.csv/legit.scv not found in %s — files: %s",
                        llm_dir.name,
                        [f.name for f in sorted(llm_dir.iterdir())])

        phish_f = _find_csv_in_folder(llm_dir, ["phising", "phishing"])
        if phish_f:
            df = _read_csv(phish_f)
            rows.extend(_extract_rows_forced(df, 1, "llm_phising"))
        else:
            log.warning("  phising.csv not found in %s — files: %s",
                        llm_dir.name,
                        [f.name for f in sorted(llm_dir.iterdir())])

    if not rows:
        log.error("No rows extracted. Check ZIP structure and CSV column names.")
        return ""

    human_n = sum(1 for r in rows if r["label"] == 0)
    ai_n    = sum(1 for r in rows if r["label"] == 1)

    if human_n == 0:
        log.error("Zero human rows — check human-generated/ folder.")
        return ""
    if ai_n == 0:
        log.error("Zero AI rows — check llm-generated/ folder.")
        return ""

    df_out = (pd.DataFrame(rows)
              .drop_duplicates(subset=["body"])
              .sample(frac=1, random_state=42)
              .reset_index(drop=True))

    out = PROC_DIR / "ai_human_training.csv"
    df_out.to_csv(out, index=False)
    log.info("✓ AI vs Human: %d total (%d human, %d AI) → %s",
             len(df_out), human_n, ai_n, out)
    return str(out)


# ─────────────────────────────────────────────────────────────────────────────
# BUILD SAFE vs UNSAFE TRAINING CSV
# ─────────────────────────────────────────────────────────────────────────────

def build_safe_unsafe_csv() -> str:
    """
    Sources:
      spamassasin.csv              → safe=0  (forced, SpamAssassin ham)
      phishing_email.csv           → unsafe=1 (column-detected or forced)
      human-generated/legit.csv    → safe=0  (bonus: human legit emails)
      human-generated/phising.csv  → unsafe=1 (bonus: human phishing emails)
    """
    try:
        import pandas as pd
    except ImportError:
        log.error("pip install pandas"); return ""

    log.info("=== Building Safe vs Unsafe training dataset ===")
    rows = []

    # ── spamassasin.csv → safe=0 ───────────────────────────────────────────
    if not SPAMASSASIN_CSV.exists():
        log.error("spamassasin.csv NOT FOUND at: %s", SPAMASSASIN_CSV)
    else:
        df = _read_csv(SPAMASSASIN_CSV)
        # SpamAssassin is all ham — force label=0 if no label column
        rows.extend(_extract_rows_with_label(df, "spamassassin", safe_fallback=True))

    # ── phishing_email.csv → unsafe=1 ─────────────────────────────────────
    if not PHISHING_CSV.exists():
        log.error("phishing_email.csv NOT FOUND at: %s", PHISHING_CSV)
    else:
        df = _read_csv(PHISHING_CSV)
        rows.extend(_extract_rows_with_label(df, "phishing_email", phishing_fallback=True))

    # ── Bonus: human-generated CSVs from the ZIP ───────────────────────────
    if _ensure_extracted():
        human_dir = _find_folder_recursive(EXTRACT_DIR, ["human-generated","human generated"])
        if human_dir:
            legit_f = _find_csv_in_folder(human_dir, ["legit"])
            if legit_f:
                df = _read_csv(legit_f)
                rows.extend(_extract_rows_forced(df, 0, "human_legit_safe"))

            phish_f = _find_csv_in_folder(human_dir, ["phising","phishing"])
            if phish_f:
                df = _read_csv(phish_f)
                rows.extend(_extract_rows_forced(df, 1, "human_phising_unsafe"))

    if not rows:
        log.error("No rows loaded for Safe vs Unsafe model.")
        return ""

    safe_n   = sum(1 for r in rows if r["label"] == 0)
    unsafe_n = sum(1 for r in rows if r["label"] == 1)

    if safe_n == 0:
        log.error("Zero safe rows — check spamassasin.csv")
        return ""
    if unsafe_n == 0:
        log.error("Zero unsafe rows — check phishing_email.csv")
        return ""

    df_out = (pd.DataFrame(rows)
              .drop_duplicates(subset=["body"])
              .sample(frac=1, random_state=42)
              .reset_index(drop=True))

    out = PROC_DIR / "safe_unsafe_training.csv"
    df_out.to_csv(out, index=False)
    log.info("✓ Safe vs Unsafe: %d total (%d safe, %d unsafe) → %s",
             len(df_out), safe_n, unsafe_n, out)
    return str(out)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Prepare ForensIQ training datasets")
    p.add_argument("--ai-human",    action="store_true")
    p.add_argument("--safe-unsafe", action="store_true")
    p.add_argument("--all",         action="store_true")
    args = p.parse_args()
    build_all = args.all or (not args.ai_human and not args.safe_unsafe)

    try:
        import pandas
    except ImportError:
        print("ERROR: pip install pandas scikit-learn joblib numpy")
        sys.exit(1)

    print("\n" + "="*68)
    print("FORENSIQ DATASET BUILDER")
    print("="*68)
    print(f"Project root  : {BASE_DIR}")
    print(f"human-llm.zip : {'✓' if AI_HUMAN_ZIP.exists() else '✗ MISSING'}  {AI_HUMAN_ZIP}")
    print(f"spamassasin   : {'✓' if SPAMASSASIN_CSV.exists() else '✗ MISSING'}  {SPAMASSASIN_CSV}")
    print(f"phishing_email: {'✓' if PHISHING_CSV.exists() else '✗ MISSING'}  {PHISHING_CSV}")
    print("="*68 + "\n")

    if args.ai_human or build_all:
        path = build_ai_human_csv()
        print(f"\n{'✓' if path else '✗'} AI vs Human CSV: {path or 'FAILED'}")

    if args.safe_unsafe or build_all:
        path = build_safe_unsafe_csv()
        print(f"\n{'✓' if path else '✗'} Safe vs Unsafe CSV: {path or 'FAILED'}")

    print("\n" + "="*68)
    print("NEXT STEPS:")
    print("  python src/ml_models/train_ai_human.py")
    print("  python src/ml_models/train_safe_unsafe.py")
    print("  python run.py")
    print("="*68)