# ============================================================
# FILE: src/explainability/explanation_report.py
# PASTE AS: src/explainability/explanation_report.py
# ============================================================
"""
Generates structured report data and PDF forensic reports.
Uses fpdf2 library. Falls back to basic text if fpdf2 not installed.
Run: pip install fpdf2
"""

import os
import datetime
import uuid


# ─────────────────────────────────────────────────────────────
# REPORT DATA BUILDER
# ─────────────────────────────────────────────────────────────

def generate_report_data(fields: dict, ai_result: dict, forensic: dict) -> dict:
    """
    Assemble all analysis outputs into a structured report dict.
    Passed to generate_pdf_report() and shown in result.html.
    """
    risk    = forensic.get("risk_score", 0)
    factors = forensic.get("factors",    [])
    signals = (ai_result or {}).get("signals", [])

    return {
        "report_id":    _generate_id(),
        "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),

        "email_summary": {
            "subject":       fields.get("subject",        ""),
            "sender":        fields.get("sender_email",   ""),
            "sender_domain": fields.get("sender_domain",  ""),
            "sender_name":   fields.get("sender_name",    ""),
            "date_sent":     fields.get("date_sent",      ""),
            "source_type":   fields.get("source_type",    ""),
            "email_hash":    fields.get("email_hash_sha256", ""),
            "language":      fields.get("language",       ""),
            "word_count":    fields.get("word_count",     0),
            "url_count":     fields.get("url_count",      0),
            "attachment_count": fields.get("attachment_count", 0),
        },

        "ai_detection": {
            "label":       (ai_result or {}).get("label",       "Unknown"),
            "confidence":  (ai_result or {}).get("confidence",  0),
            "ai_score":    (ai_result or {}).get("ai_score",    0),
            "human_score": (ai_result or {}).get("human_score", 0),
            "signals":     signals[:10],
        },

        "network": {
            "ip_chain":    forensic.get("ip_chain",    ""),
            "geolocation": forensic.get("geolocation", ""),
            "isp":         forensic.get("isp",         ""),
            "port":        forensic.get("port",        "25/587 SMTP"),
            "proxy":       forensic.get("proxy",       False),
            "hosting":     forensic.get("hosting",     False),
            "ip_hidden":   fields.get("ip_hidden",     False),
            "ip_provider": fields.get("ip_provider_label", ""),
            "mac_note":    "MAC address not recoverable from email headers",
        },

        "authentication": {
            "spf":   forensic.get("spf",   "unknown"),
            "dkim":  forensic.get("dkim",  "unknown"),
            "dmarc": fields.get("dmarc_result", "unknown"),
            "spoof": forensic.get("spoof", False),
        },

        "domain": {
            "domain":     fields.get("sender_domain", ""),
            "created":    forensic.get("domain_created",   ""),
            "age":        forensic.get("domain_age",       ""),
            "expires":    forensic.get("domain_expires",   ""),
            "registrar":  forensic.get("domain_registrar", ""),
            "org":        forensic.get("domain_org",       ""),
        },

        "email_existence": {
            "status":      forensic.get("email_exists_status", "unknown"),
            "smtp_server": forensic.get("email_smtp_server",   ""),
            "smtp_code":   forensic.get("email_smtp_code",     0),
            "note":        forensic.get("email_exists_note",   ""),
        },

        "content": {
            "url_count":       fields.get("url_count",          0),
            "suspicious_urls": fields.get("suspicious_urls",    []),
            "attachment_count":fields.get("attachment_count",   0),
            "attachment_names":fields.get("attachment_names",   []),
            "is_temp_mail":    fields.get("is_temp_mail",       False),
            "is_anonymous":    fields.get("is_anonymous",       False),
            "subscribed":      forensic.get("is_subscribed_email", False),
            "keyword_score":   forensic.get("keyword_score",    0),
            "phishing_campaign":forensic.get("phishing_campaign",""),
            "url_summary":     forensic.get("url_risk_summary", ""),
            "attachment_risks":forensic.get("attachment_risks", ""),
        },

        "intelligence": {
            "phones":         forensic.get("phones",            ""),
            "social_links":   forensic.get("social_links",      ""),
            "gravatar":       forensic.get("gravatar_found",    False),
            "google_account": forensic.get("google_account_exists", False),
            "breach_count":   forensic.get("breach_count",     0),
            "osint_summary":  forensic.get("osint_summary",    ""),
            "phishing_host":  forensic.get("phishing_host",    ""),
        },

        "ml_results": {
            "bert_label":      forensic.get("bert_result",   {}).get("label",     ""),
            "bert_confidence": forensic.get("bert_result",   {}).get("confidence",0),
            "ensemble_label":  forensic.get("ensemble_result",{}).get("label",    ""),
            "ensemble_score":  forensic.get("ensemble_result",{}).get("score",    0),
        },

        "verdict": {
            "risk_score":     risk,
            "risk_level":     forensic.get("level",          "LOW"),
            "classification": forensic.get("classification", "Unknown"),
            "risk_factors":   factors[:15],
        },
    }


# ─────────────────────────────────────────────────────────────
# PDF REPORT GENERATOR
# ─────────────────────────────────────────────────────────────

def generate_pdf_report(report_data: dict, output_path: str) -> str:
    """
    Generate a PDF forensic report.
    Returns the output file path on success, empty string on failure.
    """
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        from fpdf import FPDF
        return _build_pdf(report_data, output_path)
    except ImportError:
        # fpdf2 not installed — create a plain text report instead
        return _build_text_report(report_data, output_path.replace(".pdf", ".txt"))
    except Exception as e:
        print(f"[explanation_report] PDF error: {e}")
        return _build_text_report(report_data, output_path.replace(".pdf", ".txt"))


def _build_pdf(report_data: dict, output_path: str) -> str:
    """Build the actual PDF using fpdf2."""
    from fpdf import FPDF

    # ── Colors ──────────────────────────────────────────────
    DARK_BG   = (13,  21,  32)
    ACCENT    = (0,   212, 255)
    DANGER    = (255, 76,  106)
    SUCCESS   = (57,  255, 20)
    TEXT      = (200, 220, 232)
    MUTED     = (74,  104, 128)
    WHITE     = (255, 255, 255)
    SECTION_BG= (15,  30,  48)

    class ForensicPDF(FPDF):
        def header(self):
            # Header bar
            self.set_fill_color(*DARK_BG)
            self.rect(0, 0, 210, 18, "F")
            self.set_font("Helvetica", "B", 13)
            self.set_text_color(*ACCENT)
            self.set_y(5)
            self.cell(0, 8, "ForensIQ — Email Forensic Intelligence Report", align="C")
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*MUTED)
            rid = report_data.get("report_id", "")
            gen = report_data.get("generated_at", "")
            self.set_y(12)
            self.cell(0, 4, f"Report ID: {rid}   |   Generated: {gen}", align="C")
            self.ln(6)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "I", 7)
            self.set_text_color(*MUTED)
            self.cell(0, 4, f"Page {self.page_no()} — ForensIQ Cybercrime Investigation System — CONFIDENTIAL", align="C")

    pdf = ForensicPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(12, 22, 12)
    pdf.add_page()

    # ── Background ──────────────────────────────────────────
    pdf.set_fill_color(*DARK_BG)
    pdf.rect(0, 0, 210, 297, "F")

    def section_header(title: str, color=ACCENT):
        pdf.set_fill_color(*SECTION_BG)
        pdf.set_text_color(*color)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 7, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    def kv(key: str, value, color=None):
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*MUTED)
        pdf.cell(52, 5, f"{key}:", border="B")
        pdf.set_font("Helvetica", "", 8)
        val_str = str(value)[:100] if value else "—"
        if color:
            pdf.set_text_color(*color)
        else:
            pdf.set_text_color(*TEXT)
        pdf.cell(0, 5, val_str, border="B", new_x="LMARGIN", new_y="NEXT")

    def bullet(text: str, color=TEXT):
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*color)
        pdf.cell(6, 5, "")
        pdf.cell(0, 5, f"► {str(text)[:120]}", new_x="LMARGIN", new_y="NEXT")

    # ── 1. VERDICT BANNER ───────────────────────────────────
    v       = report_data.get("verdict", {})
    ai_det  = report_data.get("ai_detection", {})
    risk    = v.get("risk_score", 0)
    cls     = v.get("classification", "Unknown")
    level   = v.get("risk_level", "LOW")
    ai_lbl  = ai_det.get("label", "Unknown")

    banner_color = DANGER if cls == "Unsafe" else SUCCESS
    pdf.set_fill_color(*banner_color)
    pdf.set_text_color(*DARK_BG)
    pdf.set_font("Helvetica", "B", 12)
    verdict_text = f"{'⚠ UNSAFE / PHISHING' if cls == 'Unsafe' else '✓ SAFE'}   |   AI/Human: {ai_lbl}   |   Risk Score: {int(risk)}/100 ({level})"
    pdf.cell(0, 11, verdict_text, fill=True, align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # ── 2. EMAIL SUMMARY ────────────────────────────────────
    s = report_data.get("email_summary", {})
    section_header("1. EMAIL SUMMARY")
    kv("Subject",         s.get("subject", ""))
    kv("Sender",          s.get("sender",  ""), ACCENT)
    kv("Sender Name",     s.get("sender_name", ""))
    kv("Domain",          s.get("sender_domain",""))
    kv("Date Sent",       s.get("date_sent",""))
    kv("Language",        s.get("language",""))
    kv("Word Count",      s.get("word_count",""))
    kv("URLs Found",      s.get("url_count",""))
    kv("Attachments",     s.get("attachment_count",""))
    kv("Email Hash",      (s.get("email_hash","") or "")[:32] + "...")
    kv("Source Type",     s.get("source_type",""))
    pdf.ln(2)

    # ── 3. AI vs HUMAN ──────────────────────────────────────
    section_header("2. AI vs HUMAN DETECTION")
    ai_color = DANGER if ai_lbl == "AI" else SUCCESS
    kv("Verdict",      ai_lbl,   ai_color)
    kv("Confidence",   f"{round(float(ai_det.get('confidence',0))*100,1)}%")
    kv("AI Score",     ai_det.get("ai_score",""))
    kv("Human Score",  ai_det.get("human_score",""))
    pdf.ln(1)
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 4, "Detection signals:", new_x="LMARGIN", new_y="NEXT")
    for sig in ai_det.get("signals", [])[:8]:
        sig_color = DANGER if "⚠" in sig else SUCCESS
        bullet(sig, sig_color)
    pdf.ln(2)

    # ── 4. NETWORK ──────────────────────────────────────────
    n = report_data.get("network", {})
    section_header("3. NETWORK INTELLIGENCE")
    if n.get("ip_hidden"):
        kv("IP Status",    f"HIDDEN by {n.get('ip_provider','')}", DANGER)
    else:
        kv("IP Chain",     n.get("ip_chain",""), ACCENT)
    kv("Geolocation",  n.get("geolocation","") or ("Not available (IP hidden)" if n.get("ip_hidden") else "—"))
    kv("ISP / ASN",    n.get("isp","") or ("Not available (IP hidden)" if n.get("ip_hidden") else "—"))
    kv("Port",         n.get("port",""))
    kv("Proxy / VPN",  "YES ⚠" if n.get("proxy") else "No", DANGER if n.get("proxy") else SUCCESS)
    kv("Hosting IP",   "YES ⚠" if n.get("hosting") else "No")
    kv("MAC Address",  "N/A — stripped at first router hop")
    pdf.ln(2)

    # ── 5. AUTHENTICATION ───────────────────────────────────
    a = report_data.get("authentication", {})
    section_header("4. EMAIL AUTHENTICATION")
    kv("SPF",   a.get("spf","").upper(),  SUCCESS if a.get("spf")=="pass" else DANGER)
    kv("DKIM",  a.get("dkim","").upper(), SUCCESS if a.get("dkim")=="pass" else DANGER)
    kv("DMARC", a.get("dmarc","").upper(),SUCCESS if a.get("dmarc")=="pass" else DANGER)
    kv("Spoof", "YES ⚠" if a.get("spoof") else "No", DANGER if a.get("spoof") else SUCCESS)
    pdf.ln(2)

    # ── 6. DOMAIN INFO ──────────────────────────────────────
    d = report_data.get("domain", {})
    section_header("5. DOMAIN REGISTRATION INFO")
    kv("Domain",     d.get("domain",""))
    kv("Created",    d.get("created",""), DANGER if d.get("age","") and "days" in d.get("age","") else ACCENT)
    kv("Age",        d.get("age",""),     DANGER if d.get("age","") and "days" in d.get("age","") else TEXT)
    kv("Expires",    d.get("expires",""))
    kv("Registrar",  d.get("registrar",""))
    kv("Organisation",d.get("org",""))
    pdf.ln(2)

    # ── 7. EMAIL EXISTENCE ──────────────────────────────────
    e = report_data.get("email_existence", {})
    section_header("6. EMAIL EXISTENCE CHECK (SMTP)")
    status = e.get("status","unknown")
    status_map = {
        "exists":     ("✓ EMAIL EXISTS",           SUCCESS),
        "not_exists": ("✗ EMAIL DOES NOT EXIST",   DANGER),
        "catch_all":  ("⚑ CATCH-ALL SERVER",       (240,165,0)),
        "blocked":    ("⊘ SMTP CHECK BLOCKED",     MUTED),
        "unknown":    ("? INCONCLUSIVE",            MUTED),
    }
    status_text, status_color = status_map.get(status, ("? Unknown", MUTED))
    kv("SMTP Status",  status_text,             status_color)
    kv("SMTP Server",  e.get("smtp_server",""))
    kv("SMTP Code",    e.get("smtp_code",""))
    kv("Note",         e.get("note","")[:120])
    pdf.ln(2)

    # ── 8. CONTENT ANALYSIS ─────────────────────────────────
    c = report_data.get("content", {})
    section_header("7. CONTENT ANALYSIS")
    kv("Keyword Score",   f"{c.get('keyword_score',0)} / 100",
       DANGER if c.get("keyword_score",0) > 50 else TEXT)
    kv("URL Summary",     c.get("url_summary",""))
    kv("Phishing Campaign",c.get("phishing_campaign","") or "None detected")
    kv("Attachment Risks",c.get("attachment_risks",""))
    kv("Temp Mail",       "YES ⚠" if c.get("is_temp_mail") else "No",
       DANGER if c.get("is_temp_mail") else SUCCESS)
    kv("Subscribed Email",c.get("subscribed","") and "YES" or "No")
    pdf.ln(2)

    # ── 9. ML RESULTS ───────────────────────────────────────
    ml = report_data.get("ml_results", {})
    section_header("8. ML MODEL RESULTS")
    bert_lbl = ml.get("bert_label","")
    ens_lbl  = ml.get("ensemble_label","")
    kv("BERT Label",      bert_lbl, DANGER if bert_lbl=="Phishing" else SUCCESS)
    kv("BERT Confidence", f"{round(float(ml.get('bert_confidence',0))*100,1)}%")
    kv("Ensemble Label",  ens_lbl,  DANGER if ens_lbl=="Phishing" else SUCCESS)
    kv("Ensemble Score",  f"{round(float(ml.get('ensemble_score',0))*100,1)}%")
    pdf.ln(2)

    # ── 10. INTELLIGENCE ────────────────────────────────────
    i = report_data.get("intelligence", {})
    section_header("9. OSINT / INTELLIGENCE")
    kv("Phone Numbers",   i.get("phones","") or "None found")
    kv("Phishing Host",   i.get("phishing_host","") or "None detected",
       DANGER if i.get("phishing_host") else SUCCESS)
    kv("Gravatar Profile",i.get("gravatar","") and "Found" or "Not found")
    kv("Google Account",  i.get("google_account","") and "Confirmed" or "Not confirmed")
    kv("Breach Count",    str(i.get("breach_count",0)),
       DANGER if i.get("breach_count",0) > 0 else SUCCESS)
    kv("OSINT Summary",   i.get("osint_summary","")[:100])
    pdf.ln(2)

    # ── 11. RISK VERDICT ────────────────────────────────────
    section_header("10. RISK VERDICT", banner_color)
    kv("Risk Score",      f"{int(risk)} / 100",   banner_color)
    kv("Risk Level",      level,                   banner_color)
    kv("Classification",  cls,                     banner_color)
    pdf.ln(2)
    if v.get("risk_factors"):
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*MUTED)
        pdf.cell(0, 4, "Risk factors:", new_x="LMARGIN", new_y="NEXT")
        for factor in v.get("risk_factors", [])[:15]:
            bullet(factor, DANGER)

    # ── Save ────────────────────────────────────────────────
    pdf.output(output_path)
    return output_path


def _build_text_report(report_data: dict, output_path: str) -> str:
    """Fallback plain-text report when fpdf2 is not installed."""
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        lines = [
            "=" * 70,
            "  ForensIQ — Email Forensic Intelligence Report",
            f"  Report ID : {report_data.get('report_id','')}",
            f"  Generated : {report_data.get('generated_at','')}",
            "=" * 70, "",
        ]
        def section(title):
            lines.extend(["", f"── {title} ──", "-" * 50])
        def kv(k, v):
            lines.append(f"  {k:<22}: {v}")

        s = report_data.get("email_summary", {})
        section("EMAIL SUMMARY")
        kv("Subject",    s.get("subject",""))
        kv("Sender",     s.get("sender",""))
        kv("Domain",     s.get("sender_domain",""))
        kv("Date Sent",  s.get("date_sent",""))

        ai = report_data.get("ai_detection", {})
        section("AI vs HUMAN DETECTION")
        kv("Verdict",    ai.get("label",""))
        kv("Confidence", f"{round(float(ai.get('confidence',0))*100,1)}%")
        for sig in ai.get("signals",[])[:5]:
            lines.append(f"    {sig}")

        v = report_data.get("verdict", {})
        section("RISK VERDICT")
        kv("Risk Score",   f"{v.get('risk_score',0)} / 100")
        kv("Level",        v.get("risk_level",""))
        kv("Classification",v.get("classification",""))
        for f in v.get("risk_factors",[])[:10]:
            lines.append(f"    ► {f}")

        lines.extend(["", "=" * 70,
                       "  NOTE: Install fpdf2 for full PDF report: pip install fpdf2",
                       "=" * 70])

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return output_path
    except Exception as e:
        print(f"[explanation_report] Text report error: {e}")
        return ""


def _generate_id() -> str:
    return "FIQ-" + uuid.uuid4().hex[:8].upper()