# ============================================================
# FILE: app/routes.py  — FINAL UPDATED VERSION
# ============================================================
import os, csv, json, uuid, datetime
from functools import wraps
from pathlib import Path
from flask import (Blueprint, render_template, request, redirect,
                   url_for, session, flash, send_file, jsonify)
from src.autopsy.email_autopsy import EmailAutopsy, format_for_dataframe
from src.ml_models.human_vs_ai import detect_ai_or_human
from src.dashboard.history_manager import (
    save_history, get_user_history, get_history_detail,
    delete_history_record, clear_user_history, get_user_stats)

try:
    from src.ml_models.safe_unsafe_classifier import classify_safe_unsafe
    _SU_AVAILABLE = True
except ImportError:
    _SU_AVAILABLE = False

try:
    from src.ml_models.dataset_growth import growth_manager
    _GROWTH_AVAILABLE = True
except ImportError:
    _GROWTH_AVAILABLE = False

bp = Blueprint("main", __name__)
BASE_DIR       = Path(__file__).resolve().parent.parent
UPLOAD_FOLDER  = BASE_DIR / "data"     / "raw"
DATASET_FOLDER = BASE_DIR / "datasets" / "uploaded_datasets"
REPORTS_FOLDER = BASE_DIR / "reports"
UNSAFE_DIR     = BASE_DIR / "datasets" / "unsafe_emails"
ALLOWED_EMAIL_EXTS = {".eml", ".txt", ".msg"}
for d in [UPLOAD_FOLDER, DATASET_FOLDER, REPORTS_FOLDER, UNSAFE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated

@bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))

@bp.route("/dashboard")
@login_required
def dashboard():
    stats = get_user_stats(session["user_id"])
    if _GROWTH_AVAILABLE:
        try:
            stats["growth"] = growth_manager.get_stats()
        except Exception:
            stats["growth"] = {}
    return render_template("dashboard.html", stats=stats)

@bp.route("/home")
@login_required
def home():
    return render_template("home.html")

@bp.route("/analyze/file", methods=["POST"])
@login_required
def analyze_file():
    uploaded = request.files.get("email_file")
    if not uploaded or uploaded.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("main.home"))
    ext = os.path.splitext(uploaded.filename)[1].lower()
    if ext not in ALLOWED_EMAIL_EXTS:
        flash("Only .eml, .txt, or .msg files are allowed.", "danger")
        return redirect(url_for("main.home"))
    raw_bytes = uploaded.read()
    fields    = EmailAutopsy().autopsy_from_bytes(raw_bytes)
    fields["source_type"] = "file"
    result = _run_full_pipeline(
        subject=fields.get("subject",""), body=fields.get("body_text",""),
        sender=fields.get("sender_email",""), fields=fields, source="file")
    save_history(user_id=session["user_id"], analysis_type="file",
        input_summary=uploaded.filename,
        ai_or_human=result["ai_result"]["label"],
        classification=result["forensic"].get("classification","N/A"),
        risk_score=result["forensic"].get("risk_score",0.0),
        sender_email=fields.get("sender_email",""),
        ip_address="; ".join(fields.get("ip_addresses",[])),
        result=result)
    return render_template("result.html", result=result, autopsy=fields,
        ai_result=result["ai_result"], forensic=result["forensic"],
        su_result=result["su_result"], anon=result["anonymity"],
        sender_id=result.get("sender_identity",{}), readonly=False)

@bp.route("/analyze/manual", methods=["POST"])
@login_required
def analyze_manual():
    subject  = request.form.get("subject","")
    sender   = request.form.get("sender_email","")
    body     = request.form.get("body","")
    urls     = [u.strip() for u in request.form.get("urls","").splitlines() if u.strip()]
    if not body.strip():
        flash("Email body is required.", "danger")
        return redirect(url_for("main.home"))
    fields = EmailAutopsy().autopsy_from_manual(subject, sender, body, urls)
    result = _run_full_pipeline(subject=subject, body=body, sender=sender,
                                fields=fields, source="manual")
    save_history(user_id=session["user_id"], analysis_type="manual",
        input_summary=subject or "(no subject)",
        ai_or_human=result["ai_result"]["label"],
        classification=result["forensic"].get("classification","N/A"),
        risk_score=result["forensic"].get("risk_score",0.0),
        sender_email=sender, ip_address="", result=result)
    return render_template("result.html", result=result, autopsy=fields,
        ai_result=result["ai_result"], forensic=result["forensic"],
        su_result=result["su_result"], anon=result["anonymity"],
        sender_id=result.get("sender_identity",{}), readonly=False)

@bp.route("/analyze/dataset", methods=["POST"])
@login_required
def analyze_dataset():
    uploaded = request.files.get("dataset_file")
    if not uploaded or uploaded.filename == "":
        flash("No dataset file selected.", "danger")
        return redirect(url_for("main.home"))
    ext = os.path.splitext(uploaded.filename)[1].lower()
    if ext not in {".csv", ".xlsx"}:
        flash("Only CSV or XLSX datasets are accepted.", "danger")
        return redirect(url_for("main.home"))
    try:
        import pandas as pd
        df = pd.read_csv(uploaded) if ext == ".csv" else pd.read_excel(uploaded)
    except Exception as e:
        flash(f"Could not read dataset: {e}", "danger")
        return redirect(url_for("main.home"))

    rows, csv_rows = [], []
    for idx, row in df.iterrows():
        subject = str(row.get("subject", row.get("Subject", row.get("Subject Line",""))))
        sender  = str(row.get("from",    row.get("From",    row.get("sender",   row.get("Sender","")))))
        body    = str(row.get("body",    row.get("Body",    row.get("content",  row.get("Content", row.get("message",""))))))
        fields  = EmailAutopsy().autopsy_from_manual(subject, sender, body)
        result  = _run_full_pipeline(subject=subject, body=body, sender=sender,
                                     fields=fields, source="dataset")
        ai, fd, su, anon = result["ai_result"], result["forensic"], result["su_result"], result["anonymity"]
        sid = result.get("sender_identity", {})
        top = (sid.get("top_candidate") or {})
        rows.append({
            "index": idx+1, "subject": subject[:70] or "—", "sender": sender[:45] or "—",
            "ai_or_human": ai["label"], "confidence": ai.get("confidence",0.0),
            "risk_score": fd.get("risk_score",0.0), "safe": fd.get("classification","N/A"),
            "su_method": su.get("method","N/A"), "anon_score": anon.get("score",0),
            "anon_verdict": anon.get("verdict",""), "step": result.get("step",1),
            "is_anonymous": sid.get("is_anonymous", False),
            "top_candidate_name": top.get("name",""),
            "top_candidate_location": top.get("location_match",""),
        })
        csv_rows.append(_build_full_csv_row(idx+1, subject, sender, body, fields, ai, fd, su, anon, sid))

    out_csv_name = f"dataset_result_{uuid.uuid4().hex[:8]}.csv"
    out_csv_path = str(REPORTS_FOLDER / out_csv_name)
    try:
        import pandas as pd
        pd.DataFrame(csv_rows).to_csv(out_csv_path, index=False)
    except Exception:
        pass
    save_history(user_id=session["user_id"], analysis_type="dataset",
        input_summary=uploaded.filename, ai_or_human="Mixed", classification="Mixed",
        risk_score=0.0, sender_email="", ip_address="",
        result={"csv_file": out_csv_name, "total": len(rows)})
    return render_template("dataset_result.html", rows=rows, total=len(rows), csv_file=out_csv_name)

@bp.route("/download/dataset/<filename>")
@login_required
def download_dataset(filename):
    safe_name = os.path.basename(filename)
    path = str(REPORTS_FOLDER / safe_name)
    if not os.path.exists(path):
        flash("File not found.", "danger")
        return redirect(url_for("main.home"))
    return send_file(path, as_attachment=True, download_name=safe_name)

@bp.route("/api/growth-stats")
@login_required
def api_growth_stats():
    if not _GROWTH_AVAILABLE:
        return jsonify({"error": "Growth manager not available"}), 503
    try:
        return jsonify(growth_manager.get_stats())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

@bp.route("/history")
@login_required
def history():
    records = get_user_history(session["user_id"], limit=100)
    return render_template("history.html", records=records)

@bp.route("/history/<int:record_id>")
@login_required
def history_detail(record_id):
    data = get_history_detail(record_id, session["user_id"])
    if not data:
        flash("Record not found.", "danger")
        return redirect(url_for("main.history"))
    r = data.get("result", {})
    return render_template("result.html", result=r, autopsy=r.get("autopsy",{}),
        ai_result=r.get("ai_result",{}), forensic=r.get("forensic",{}),
        su_result=r.get("su_result",{}), anon=r.get("anonymity",{}),
        sender_id=r.get("sender_identity",{}), readonly=True)

@bp.route("/history/<int:record_id>/delete", methods=["POST"])
@login_required
def history_delete(record_id):
    delete_history_record(record_id, session["user_id"])
    flash("Record deleted.", "success")
    return redirect(url_for("main.history"))

@bp.route("/history/clear", methods=["POST"])
@login_required
def history_clear():
    clear_user_history(session["user_id"])
    flash("All history cleared.", "success")
    return redirect(url_for("main.history"))

# =============================================================================
# CORE PIPELINE
# =============================================================================
def _run_full_pipeline(subject, body, sender, fields, source):
    ai_result = detect_ai_or_human(body, subject)
    ai_label  = ai_result["label"]
    su_result, forensic_data, anonymity, sender_identity = {}, _empty_forensic(), {"score":0,"verdict":"N/A","found":[],"missing":[]}, {}
    step_reached = 1
    _grow_ai_human(subject, body, ai_result, source)

    if ai_label == "AI":
        su_result = _classify_su(subject, body, sender)
        step_reached = 1
        forensic_data["classification"] = su_result.get("label","Unknown")
        forensic_data["risk_score"]     = su_result.get("risk_score",0.0)
    else:
        step_reached  = 2
        su_result     = _classify_su(subject, body, sender)
        _merge_su_into_forensic(su_result, forensic_data)
        forensic_data = _run_full_forensics(fields)
        _merge_su_into_forensic(su_result, forensic_data)
        _grow_safe_unsafe(subject, body, forensic_data, source)
        anonymity = _compute_anonymity(sender, fields, forensic_data)
        # Auto sender grouping
        try:
            from src.intelligence.social_sender_grouper import group_and_filter_senders
            geo_data = _parse_geo(forensic_data.get("geolocation",""))
            sender_identity = group_and_filter_senders(
                social_links=forensic_data.get("social_links_list",[]),
                sender_email=fields.get("sender_email", sender),
                sender_name=fields.get("sender_name",""),
                geo=geo_data,
                domain_info={"org": forensic_data.get("domain_org",""),
                             "registrar": forensic_data.get("domain_registrar","")})
        except Exception:
            sender_identity = {}
        if forensic_data.get("classification") == "Unsafe":
            step_reached = 3
            _save_unsafe_email(subject, sender, body, fields, forensic_data, su_result, anonymity, sender_identity)

    result = _build_result(fields, ai_result, forensic_data, su_result)
    result["anonymity"]       = anonymity
    result["step"]            = step_reached
    result["sender_identity"] = sender_identity
    return result

# ── HELPERS ──────────────────────────────────────────────────────────────────
def _classify_su(subject, body, sender):
    if _SU_AVAILABLE:
        try:
            return classify_safe_unsafe(subject, body, sender)
        except Exception: pass
    try:
        from src.ml_models.phishing_classifier import classify_email
        ph = classify_email(subject, body, sender)
        label = "Unsafe" if ph.get("label") == "Phishing" else "Safe"
        return {"label":label,"confidence":ph.get("confidence",0.5),
                "risk_score":ph.get("probability",0.0)*100,"signals":[],"method":ph.get("method","rule_based")}
    except Exception: pass
    return {"label":"Unknown","confidence":0.0,"risk_score":0.0,"signals":[],"method":"unavailable"}

def _merge_su_into_forensic(su, fd):
    if not su or su.get("label") == "Unknown": return
    fd["risk_score"]     = max(float(su.get("risk_score",0.0)), float(fd.get("risk_score",0.0)))
    fd["classification"] = "Unsafe" if fd["risk_score"] >= 45 else "Safe"
    fd["su_label"]       = su.get("label","")
    fd["su_confidence"]  = su.get("confidence",0.0)
    fd["su_method"]      = su.get("method","")
    fd["su_signals"]     = su.get("signals",[])

def _grow_ai_human(subject, body, ai_result, source):
    if not _GROWTH_AVAILABLE: return
    try:
        growth_manager.add_ai_human(subject=subject, body=body,
            ai_label=ai_result.get("label","Unknown"),
            confidence=ai_result.get("confidence",0.0), source=source)
    except Exception: pass

def _grow_safe_unsafe(subject, body, fd, source):
    if not _GROWTH_AVAILABLE: return
    try:
        growth_manager.add_safe_unsafe(subject=subject, body=body,
            classification=fd.get("classification","Unknown"),
            risk_score=fd.get("risk_score",0.0), source=source)
    except Exception: pass

def _parse_geo(geo_string):
    if not geo_string: return {}
    parts = [p.strip() for p in geo_string.replace(","," ").split()]
    return {"city": parts[0] if len(parts)>0 else "",
            "region": parts[1] if len(parts)>1 else "",
            "country": parts[-1] if len(parts)>2 else ""}

def _compute_anonymity(sender, fields, fd):
    found, missing, score = [], [], 100
    ips = fields.get("ip_addresses",[])
    if ips:   found.append(f"IP address: {ips[0]}"); score -= 15
    else:   missing.append("IP address (hidden/not found)")
    if fd.get("geolocation"):   found.append(f"Location: {fd['geolocation']}"); score -= 10
    else:   missing.append("Geolocation")
    if fd.get("domain_org") or fd.get("domain_registrar"):
        found.append(f"Domain: {fd.get('domain_org') or fd.get('domain_registrar')}"); score -= 10
    else:   missing.append("Domain registration info")
    confirmed = [l for l in fd.get("social_links_list",[]) if l.get("found") is True]
    if confirmed:
        found.append(f"Social profiles: {', '.join(l.get('platform','') for l in confirmed[:5])}"); score -= min(len(confirmed)*8,25)
    else:   missing.append("Social media profiles (no confirmed profiles found)")
    if fd.get("osint_confirmed_profiles"):   found.append(f"OSINT: {fd['osint_confirmed_profiles']}"); score -= 10
    if fd.get("gravatar_found"):   found.append("Gravatar profile found"); score -= 8
    bc = fd.get("breach_count", 0)
    if bc and int(bc) > 0:   found.append(f"Email in {bc} breach(es)"); score -= 5
    if fd.get("phones"):   found.append("Phone number(s) in email body"); score -= 7
    if fd.get("spf") == "pass" or fd.get("dkim") == "pass":
        found.append("Email auth passes (real domain)"); score -= 5
    score = max(0, min(100, score))
    verdict = ("Anonymous / No Digital Footprint" if score>=80 else
               "Mostly Anonymous" if score>=60 else
               "Partially Identifiable" if score>=40 else
               "Mostly Identifiable" if score>=20 else "Fully Identifiable")
    return {"score": score, "verdict": verdict, "found": found, "missing": missing}

def _save_unsafe_email(subject, sender, body, fields, fd, su, anon, sid):
    unsafe_csv = UNSAFE_DIR / "unsafe_emails.csv"
    top = (sid or {}).get("top_candidate") or {}
    cols = ["timestamp","sender_email","sender_name","sender_domain","subject","body_preview",
            "risk_score","classification","su_method","su_confidence","su_signals",
            "ip_addresses","geolocation","isp","domain_age","spf","dkim","spoof_detected",
            "social_links","osint_profiles","gravatar_found","anonymity_score","anonymity_verdict",
            "phones","breach_count","phishing_host","suspicious_urls","keyword_score",
            "sender_id_name","sender_id_score","sender_id_location","sender_id_qualification",
            "is_anonymous","anonymous_reason"]
    row = {
        "timestamp": datetime.datetime.utcnow().isoformat()+"Z",
        "sender_email": sender, "sender_name": fields.get("sender_name",""),
        "sender_domain": fields.get("sender_domain",""), "subject": subject[:200],
        "body_preview": body[:500], "risk_score": fd.get("risk_score",0.0),
        "classification": fd.get("classification","Unsafe"),
        "su_method": su.get("method",""), "su_confidence": round(su.get("confidence",0.0)*100,1),
        "su_signals": " | ".join(su.get("signals",[])),
        "ip_addresses": "; ".join(fields.get("ip_addresses",[])),
        "geolocation": fd.get("geolocation",""), "isp": fd.get("isp",""),
        "domain_age": fd.get("domain_age",""), "spf": fd.get("spf",""),
        "dkim": fd.get("dkim",""), "spoof_detected": str(fd.get("spoof",False)),
        "social_links": fd.get("social_links",""),
        "osint_profiles": fd.get("osint_confirmed_profiles",""),
        "gravatar_found": str(fd.get("gravatar_found",False)),
        "anonymity_score": anon.get("score",100), "anonymity_verdict": anon.get("verdict",""),
        "phones": fd.get("phones",""), "breach_count": fd.get("breach_count",0),
        "phishing_host": fd.get("phishing_host",""),
        "suspicious_urls": "; ".join(fields.get("suspicious_urls",[])),
        "keyword_score": fd.get("keyword_score",0),
        "sender_id_name": top.get("name",""), "sender_id_score": top.get("score",0),
        "sender_id_location": top.get("location_match",""),
        "sender_id_qualification": top.get("qualification",""),
        "is_anonymous": str((sid or {}).get("is_anonymous",False)),
        "anonymous_reason": (sid or {}).get("anonymous_reason",""),
    }
    try:
        file_exists = unsafe_csv.exists()
        with open(unsafe_csv, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            if not file_exists: w.writeheader()
            w.writerow(row)
    except Exception: pass

def _empty_forensic():
    return {"classification":"Unknown","risk_score":0.0,"ip_chain":"","geolocation":"","isp":"",
            "port":"25 / 587 (SMTP)","mac_address":"N/A (not in email headers)",
            "proxy":False,"hosting":False,"domain_age":"","domain_created":"","domain_expires":"",
            "domain_registrar":"","domain_org":"","nameservers":"","social_links":"","social_links_list":[],
            "phones":"","phone_lookups":"","phishing_host":"","keyword_score":0,
            "phishing_campaign":"","factors":[],"level":"","spf":"unknown","dkim":"unknown","spoof":False,
            "su_label":"","su_confidence":0.0,"su_method":"","su_signals":[],
            "email_exists_status":"unknown","email_smtp_server":"","smtp_code":"","mx_records":[],
            "catch_all":False,"email_exists_note":"","gravatar_found":False,"google_account_exists":False,
            "osint_confirmed_profiles":"","breach_count":0,"osint_summary":"","url_risk_summary":"",
            "attachment_risks":"","bert_result":{},"ensemble_result":{},"vt_attachment_results":[],
            "mail_server_provider":"","is_subscribed_email":False}

def _run_full_forensics(fields):
    fd = _empty_forensic()
    fd["spf"] = fields.get("spf_result","unknown")
    fd["dkim"] = fields.get("dkim_result","unknown")
    fd["spoof"] = fields.get("spoof_detected",False)
    ips = fields.get("ip_addresses",[])
    try:
        from src.forensic.ip_tracker import track_ips
        t = track_ips(fields.get("received_chain",[]))
        fd["ip_hidden"] = t.get("ip_hidden",False); fd["provider_label"] = t.get("provider_label","")
    except Exception: pass
    try:
        from src.forensic.ip_geolocation import get_geolocation
        if ips:
            geo = get_geolocation(ips[0])
            fd["geolocation"] = f"{geo.get('city','')}, {geo.get('region','')} {geo.get('country','')}".strip(", ")
            fd["ip_chain"] = "; ".join(ips)
    except Exception:
        if ips: fd["ip_chain"] = "; ".join(ips)
    try:
        from src.intelligence.ip_intel import get_ip_intel
        if ips:
            intel = get_ip_intel(ips[0])
            fd["isp"] = intel.get("isp", intel.get("org","")); fd["proxy"] = intel.get("proxy",False); fd["hosting"] = intel.get("hosting",False)
    except Exception: pass
    try:
        from src.forensic.spf_dkim_checker import check_spf_dkim
        domain = fields.get("sender_domain","")
        if domain:
            r = check_spf_dkim(domain); fd["spf"] = r.get("spf","unknown"); fd["dkim"] = r.get("dkim","unknown")
    except Exception: pass
    try:
        from src.forensic.spoof_detector import detect_spoof
        fd["spoof"] = detect_spoof(fields)
    except Exception: pass
    try:
        from src.forensic.anonymous_provider_detector import detect_anonymous
        r = detect_anonymous(fields.get("sender_domain",""))
        if r: fd["phishing_host"] = r
    except Exception: pass
    try:
        from src.forensic.mail_server_detector import detect_mail_server
        ms = detect_mail_server(fields.get("sender_domain",""))
        fd["mail_server_provider"] = ms.get("provider",""); fd["mx_records"] = ms.get("mx_records",[])
    except Exception: pass
    try:
        from src.intelligence.domain_intel import get_domain_info
        domain = fields.get("sender_domain","")
        if domain:
            info = get_domain_info(domain)
            fd["domain_age"] = info.get("age",""); fd["domain_created"] = str(info.get("created",""))
            fd["domain_expires"] = str(info.get("expiry","")); fd["domain_registrar"] = info.get("registrar","")
            fd["domain_org"] = info.get("org",""); fd["nameservers"] = "; ".join(info.get("nameservers",[]))
    except Exception: pass
    try:
        from src.intelligence.phone_extractor import extract_phones
        phones = extract_phones(fields.get("body_text",""))
        fd["phones"] = "; ".join(phones) if phones else ""
    except Exception: pass
    try:
        from src.forensic.url_analyzer import analyze_urls
        fd["url_risk_summary"] = analyze_urls(fields.get("urls_found",[])).get("summary","")
    except Exception: pass
    try:
        from src.intelligence.phishing_campaign import detect_campaign
        camp = detect_campaign(fields.get("body_text",""), fields.get("subject",""))
        fd["phishing_campaign"] = ", ".join(camp.get("detected",[])) or ""
    except Exception: pass
    try:
        from src.features.phishing_keywords import score_keywords
        fd["keyword_score"] = score_keywords(fields.get("subject","")+" "+fields.get("body_text","")).get("score",0)
    except Exception: pass
    try:
        from src.intelligence.email_verifier import check_subscribed_email
        fd["is_subscribed_email"] = check_subscribed_email(fields.get("body_text",""))
    except Exception: pass
    try:
        from src.features.content_features import extract_content_features
        fd["content_features"] = extract_content_features(fields.get("subject",""), fields.get("body_text",""))
    except Exception: pass
    try:
        from src.ml_models.bert_classifier import classify_phishing
        fd["bert_result"] = classify_phishing(fields.get("body_text",""), fields.get("subject",""))
    except Exception: pass
    try:
        from src.ml_models.ensemble_model import ensemble_predict
        fd["ensemble_result"] = ensemble_predict(fields.get("subject",""), fields.get("body_text",""), fields.get("sender_email",""))
    except Exception: pass
    try:
        from src.malware_analysis.attachment_detector import detect_suspicious_attachments
        flagged = detect_suspicious_attachments(fields.get("attachments",[]))
        fd["attachment_risks"] = "; ".join(a.get("name","") for a in flagged) if flagged else ""
    except Exception: pass
    try:
        from src.malware_analysis.virustotal_scan import scan_all_attachments
        fd["vt_attachment_results"] = scan_all_attachments(fields.get("attachments",[]))
    except Exception: pass
    try:
        from src.risk_engine.risk_scoring import calculate_risk
        risk = calculate_risk(fields, fd)
        fd["risk_score"] = float(risk.get("score",0.0)); fd["level"] = risk.get("level","")
        fd["factors"] = risk.get("factors",[]); fd["classification"] = "Unsafe" if fd["risk_score"] >= 45 else "Safe"
    except Exception:
        score = 0
        if fields.get("is_temp_mail"): score += 30
        if fd.get("spoof"): score += 25
        if fields.get("suspicious_urls"): score += 20
        if fields.get("attachment_count",0) > 0: score += 15
        fd["risk_score"] = min(score,100); fd["classification"] = "Unsafe" if score > 50 else "Safe"
    try:
        from src.utils.evidence_saver import save_evidence
        save_evidence(fields, fd)
    except Exception: pass
    try:
        from src.utils.splunk_logger import log_to_splunk
        log_to_splunk(fields, fd)
    except Exception: pass
    try:
        from src.explainability.explanation_report import generate_pdf_report
        fd["pdf_report"] = generate_pdf_report(fields, fd)
    except Exception: pass
    # OSINT / Social links
    try:
        from src.intelligence.email_osint import run_email_osint
        osint = run_email_osint(fields.get("sender_email",""), fields.get("sender_name",""))
        confirmed = [p for p in osint.get("social_profiles",[]) if p.get("found") is True]
        all_links = confirmed + osint.get("search_links",[])
        fd["social_links_list"] = _dedup_social(all_links)
        fd["social_links"] = "; ".join(lk.get("url","") for lk in fd["social_links_list"])
        gravatar = osint.get("gravatar",{})
        fd["gravatar_found"] = bool(gravatar.get("found") if isinstance(gravatar,dict) else False)
        fd["google_account_exists"] = bool(osint.get("google_account",{}).get("exists",False))
        fd["osint_confirmed_profiles"] = ", ".join(p.get("platform","") for p in confirmed[:6])
        fd["osint_summary"] = osint.get("summary","")
        fd["breach_count"] = len(osint.get("breaches",[]))
    except Exception:
        try:
            from src.intelligence.social_lookup import find_social_links
            links = find_social_links(fields.get("sender_email",""), fields.get("sender_name",""))
            fd["social_links_list"] = links; fd["social_links"] = "; ".join(lk.get("url","") for lk in links)
        except Exception: pass
    try:
        from src.intelligence.email_verifier import verify_email_full
        ev = verify_email_full(fields.get("sender_email",""))
        fd["email_exists_status"] = ev.get("exists_status","unknown")
        fd["email_smtp_server"] = ev.get("smtp_server",""); fd["smtp_code"] = ev.get("smtp_code","")
        fd["mx_records"] = ev.get("mx_records",[]); fd["catch_all"] = ev.get("catch_all",False)
        fd["email_exists_note"] = ev.get("note","")
        if not fd.get("domain_age") and ev.get("whois"):
            w = ev["whois"]; fd["domain_age"] = w.get("age",""); fd["domain_created"] = str(w.get("created",""))
            fd["domain_expires"] = str(w.get("expiry","")); fd["domain_registrar"] = w.get("registrar","")
            fd["domain_org"] = w.get("org",""); fd["nameservers"] = "; ".join(w.get("nameservers",[]))
    except Exception: pass
    return fd

def _build_full_csv_row(idx, subject, sender, body, fields, ai_result, fd, su, anon, sid=None):
    sid = sid or {}
    top = (sid.get("top_candidate") or {})
    is_ai     = ai_result.get("label") == "AI"
    is_unsafe = fd.get("classification") == "Unsafe"
    base = {
        "#": idx, "Pipeline Step": _step_label(ai_result, fd),
        "Subject": subject[:200], "Sender Email": sender[:200],
        "Sender Name": fields.get("sender_name",""), "Sender Domain": fields.get("sender_domain",""),
        "Recipient Email": fields.get("recipient_email",""), "Date Sent": fields.get("date_sent",""),
        "Message-ID": fields.get("message_id",""),
        "AI or Human": ai_result.get("label","Unknown"),
        "AI Confidence %": round(ai_result.get("confidence",0.0)*100,1),
        "AI/Human Method": ai_result.get("method",""),
        "Safe/Unsafe Label": fd.get("classification","N/A"),
        "Risk Score": fd.get("risk_score",0.0),
        "SU Confidence %": round(su.get("confidence",0.0)*100,1),
        "SU Signals": " | ".join(su.get("signals",[])),
        "Analysis Timestamp": datetime.datetime.utcnow().isoformat()+"Z",
    }
    if not is_ai:
        base.update({
            "Anonymity Score": anon.get("score",0), "Anonymity Verdict": anon.get("verdict","N/A"),
            "Info Found": " | ".join(anon.get("found",[])), "Info Missing": " | ".join(anon.get("missing",[])),
            "IP Addresses": "; ".join(fields.get("ip_addresses",[])),
            "Geolocation": fd.get("geolocation",""), "ISP / Host": fd.get("isp",""),
            "Proxy/VPN": str(fd.get("proxy",False)), "SPF Result": fd.get("spf",""),
            "DKIM Result": fd.get("dkim",""), "Spoof Detected": str(fd.get("spoof",False)),
            "Domain Age": fd.get("domain_age",""), "Domain Created": fd.get("domain_created",""),
            "Domain Expires": fd.get("domain_expires",""), "Domain Registrar": fd.get("domain_registrar",""),
            "Domain Org": fd.get("domain_org",""), "Email Exists Status": fd.get("email_exists_status",""),
            "SMTP Server": fd.get("email_smtp_server",""), "MX Records": "; ".join(fd.get("mx_records",[])),
            "Phone Numbers": fd.get("phones",""),
            "Suspicious URLs": "; ".join(fields.get("suspicious_urls",[])),
            "Keyword Score": fd.get("keyword_score",0), "Attachment Count": fields.get("attachment_count",0),
        })
    if not is_ai and is_unsafe:
        base.update({
            "Social Links": fd.get("social_links",""), "OSINT Profiles": fd.get("osint_confirmed_profiles",""),
            "Gravatar Found": str(fd.get("gravatar_found",False)), "Breach Count": fd.get("breach_count",0),
            "Phishing Campaign": fd.get("phishing_campaign",""), "Risk Factors": " | ".join(fd.get("factors",[])),
            "Phishing Host": fd.get("phishing_host",""), "URL Risk Summary": fd.get("url_risk_summary",""),
            "Attachment Risks": fd.get("attachment_risks",""),
            "Sender ID Name": top.get("name",""), "Sender ID Score": top.get("score",0),
            "Sender ID Location": top.get("location_match",""), "Sender ID Qualification": top.get("qualification",""),
            "Sender ID Profile Count": top.get("profile_count",0),
            "Is Anonymous": str(sid.get("is_anonymous",False)), "Anonymous Reason": sid.get("anonymous_reason",""),
            "Filter City": (sid.get("filter_used") or {}).get("city",""),
            "Filter State": (sid.get("filter_used") or {}).get("state",""),
            "Filter Country": (sid.get("filter_used") or {}).get("country",""),
            "Total Profiles Found": sid.get("total_profiles_found",0),
        })
    return base

def _step_label(ai_result, fd):
    if ai_result.get("label") == "AI": return "Step 1: AI/Machine Generated"
    if fd.get("classification") == "Unsafe": return "Step 3: Human — Unsafe + OSINT"
    return "Step 2: Human — Safe + OSINT"

def _dedup_social(links):
    seen = {}
    for lk in links:
        p = lk.get("platform", lk.get("name",""))
        if p and p not in seen: seen[p] = lk
    return list(seen.values())

def _build_result(fields, ai_result, forensic_data, su_result=None):
    return {"autopsy": fields, "ai_result": ai_result, "forensic": forensic_data,
            "su_result": su_result or {},
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}
