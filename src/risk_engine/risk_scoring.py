# ============================================================
# FILE: src/risk_engine/risk_scoring.py
# PASTE AS: src/risk_engine/risk_scoring.py
#
# FIXES:
#   1. Keyword score no longer divided by 3 — now uses full weight
#   2. Keyword score cap raised from 20 to 40 points
#   3. Campaign detection adds up to 30 points (was 20)
#   4. Subject line scanned separately for critical keywords
#   5. Prize/lottery/scam patterns detected directly in body
#   6. Unsafe threshold lowered from 50 to 45 for borderline cases
# ============================================================
"""
Multi-factor risk scoring engine.
Combines all forensic signals into a 0-100 risk score.
"""
import re


def calculate_risk(fields: dict, forensic: dict) -> dict:
    """
    Calculate overall email risk score from all forensic signals.
    Returns: { score (0-100), level, factors, classification }
    """
    score   = 0
    factors = []

    subject  = fields.get("subject",   "").lower()
    body     = fields.get("body_text", "").lower()
    full_text= subject + " " + body

    # ── 1. SPF / DKIM ───────────────────────────────────────
    spf  = str(forensic.get("spf",  fields.get("spf_result",  ""))).lower()
    dkim = str(forensic.get("dkim", fields.get("dkim_result", ""))).lower()

    if spf in ("fail", "softfail", "none", "error", "unknown"):
        score += 10
        factors.append(f"SPF {spf.upper()} — sender domain not authorized")
    elif spf == "pass":
        score -= 5

    if dkim in ("none", "fail", "error", "unknown"):
        score += 10
        factors.append(f"DKIM {dkim.upper()} — message integrity not verified")
    elif dkim == "pass":
        score -= 5

    # ── 2. Spoof Detection ──────────────────────────────────
    if forensic.get("spoof") or fields.get("spoof_detected"):
        score += 25
        factors.append("Email spoofing detected — From/Return-Path domain mismatch")

    # ── 3. Temp / Anonymous Mail ────────────────────────────
    if fields.get("is_temp_mail"):
        score += 20
        factors.append(f"Temp/disposable email provider: {fields.get('sender_domain','')}")
    if forensic.get("phishing_host") or forensic.get("is_anonymous_provider"):
        score += 15
        factors.append(f"Anonymous email provider detected: {forensic.get('phishing_host','')}")

    # ── 4. Suspicious URLs ──────────────────────────────────
    suspicious_urls = fields.get("suspicious_urls", [])
    if suspicious_urls:
        url_score = min(len(suspicious_urls) * 10, 30)
        score += url_score
        factors.append(f"{len(suspicious_urls)} suspicious URL(s) detected (+{url_score}pts)")

    # IP-based URL (very high risk)
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", full_text):
        score += 15
        factors.append("IP-address based URL found — hides real domain identity")

    # ── 5. Dangerous Attachments ────────────────────────────
    att_count = fields.get("attachment_count", 0)
    att_names = fields.get("attachment_names", [])
    if att_count > 0:
        score += 10
        factors.append(f"{att_count} attachment(s) present")
        dangerous = {".exe",".bat",".cmd",".vbs",".ps1",".js",".msi",
                     ".scr",".pif",".dll",".jar",".docm",".xlsm",".hta"}
        for name in att_names:
            import os
            ext = os.path.splitext(name)[1].lower()
            if ext in dangerous:
                score += 25
                factors.append(f"Dangerous attachment type: {ext}")
                break

    # ── 6. Phishing Keywords (FIXED — no more divide by 3) ──
    try:
        from src.features.phishing_keywords import score_keywords
        kw_result = score_keywords(full_text)
        kw_raw    = kw_result.get("score", 0)   # 0-100 raw score

        # Map raw keyword score to risk contribution:
        # 0-10   → 0 pts   (noise)
        # 11-30  → 10 pts  (low concern)
        # 31-50  → 20 pts  (medium concern)
        # 51-70  → 30 pts  (high concern)
        # 71-100 → 40 pts  (critical)
        if kw_raw > 70:
            kw_contribution = 40
        elif kw_raw > 50:
            kw_contribution = 30
        elif kw_raw > 30:
            kw_contribution = 20
        elif kw_raw > 10:
            kw_contribution = 10
        else:
            kw_contribution = 0

        if kw_contribution > 0:
            score += kw_contribution
            matched_levels = list(kw_result.get("matches", {}).keys())
            factors.append(
                f"Phishing keywords detected: score {kw_raw}/100, "
                f"{kw_result.get('count',0)} matches "
                f"({', '.join(matched_levels)}) +{kw_contribution}pts"
            )
    except Exception:
        pass

    # ── 7. Subject line critical keyword check ──────────────
    CRITICAL_SUBJECT = [
        "verify", "suspended", "urgent", "action required",
        "account limited", "winner", "won", "prize", "lottery",
        "free iphone", "free gift", "congratulations",
        "password expired", "unusual sign-in", "security alert",
        "your account", "invoice", "payment failed", "overdue",
    ]
    subject_hits = [kw for kw in CRITICAL_SUBJECT if kw in subject]
    if subject_hits:
        score += min(len(subject_hits) * 5, 15)
        factors.append(f"Suspicious subject line keywords: {', '.join(subject_hits[:3])}")

    # ── 8. Phishing Campaign Patterns ───────────────────────
    try:
        from src.intelligence.phishing_campaign import detect_campaign
        camp = detect_campaign(
            fields.get("body_text",""),
            fields.get("subject","")
        )
        if camp.get("is_phishing"):
            detected    = camp.get("detected",[])
            camp_score  = min(len(detected) * 15, 30)
            score      += camp_score
            factors.append(
                f"Phishing campaign pattern: {', '.join(detected[:3])} "
                f"+{camp_score}pts"
            )
    except Exception:
        pass

    # ── 9. Prize / Lottery / Scam body pattern ──────────────
    SCAM_PATTERNS = [
        (r"won.{0,30}(million|thousand|prize|lottery|cash|dollars)", "Prize/lottery scam pattern"),
        (r"(processing fee|transfer fee|handling fee).{0,30}\$",     "Fee-required scam pattern"),
        (r"(claim|collect|redeem).{0,30}(prize|reward|winnings)",     "Prize claim scam"),
        (r"(send|provide).{0,30}(bank.?account|routing|swift)",       "Bank details request"),
        (r"(inheritance|beneficiary|deceased|estate).{0,40}million",  "Advance fee fraud (419)"),
        (r"(free|complimentary).{0,20}(iphone|ipad|laptop|samsung)",  "Fake product giveaway"),
        (r"(only|just).{0,10}(pay|cover).{0,15}(shipping|handling)",  "Pay shipping scam"),
        (r"act.{0,10}(now|immediately|fast|quickly).{0,20}(expire|limited|hours)", "Urgency manipulation"),
    ]
    for pattern, label in SCAM_PATTERNS:
        if re.search(pattern, full_text, re.IGNORECASE):
            score += 12
            factors.append(label)

    # ── 10. Young Domain ────────────────────────────────────
    age = forensic.get("domain_age","")
    if age:
        if "days" in age or "0 yr 0 mo" in age:
            score += 20
            factors.append(f"Extremely new domain: {age}")
        elif any(f"0 yr {m} mo" in age for m in ["1","2","3"]):
            score += 15
            factors.append(f"Very new sender domain: {age}")

    # ── 11. IP / Network flags ──────────────────────────────
    if forensic.get("hosting") is True:
        score += 10
        factors.append("Sender IP is a known hosting/VPS provider")
    if forensic.get("proxy") is True:
        score += 15
        factors.append("Sender IP is a known proxy/VPN")

    # ── 12. URL count ───────────────────────────────────────
    url_count = fields.get("url_count", 0)
    if url_count > 5:
        score += 8
        factors.append(f"High URL count in body: {url_count}")

    # ── 13. Sender domain mismatch signals ──────────────────
    sender_domain = fields.get("sender_domain","").lower()
    BRAND_IMPERSONATION = [
        "paypal","amazon","microsoft","google","apple","netflix",
        "facebook","instagram","twitter","linkedin","bank","sbi",
        "hdfc","icici","chase","wellsfargo","hsbc","barclays",
    ]
    for brand in BRAND_IMPERSONATION:
        if brand in sender_domain:
            # Check if it's the real domain
            real_domains = {
                "paypal":     "paypal.com",
                "amazon":     "amazon.com",
                "microsoft":  "microsoft.com",
                "google":     "google.com",
                "apple":      "apple.com",
            }
            real = real_domains.get(brand, f"{brand}.com")
            if sender_domain != real and not sender_domain.endswith(f".{real}"):
                score += 20
                factors.append(
                    f"Brand impersonation: '{brand}' in domain "
                    f"but not the real {real}"
                )
                break

    # ── Clamp and classify ──────────────────────────────────
    score = max(0, min(score, 100))

    if score >= 70:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Threshold: 45+ = Unsafe (slightly lower than 50 for borderline cases)
    classification = "Unsafe" if score >= 45 else "Safe"

    return {
        "score":          score,
        "level":          level,
        "classification": classification,
        "factors":        factors,
    }