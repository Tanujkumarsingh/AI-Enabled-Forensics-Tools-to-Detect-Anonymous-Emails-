# ============================================================
# FINAL FORENSIC ENGINE (AI + OSINT + CONTINUOUS LEARNING)
# ============================================================

import time
import logging

log = logging.getLogger("forensiq.engine")


def run_forensics(fields: dict, is_ai_email: bool = False) -> dict:

    from src.ml_models.human_vs_ai import predict_ai_human
    from src.ml_models.safe_unsafe_classifier import classify_safe_unsafe

    # 🔥 CONTINUOUS LEARNING IMPORT
    from src.learning.continuous_learner import (
        add_to_ai_human_dataset,
        add_to_safe_unsafe_dataset
    )

    start_time = time.time()

    email_text = fields.get("body_text", "")
    sender_email = fields.get("sender_email", "")
    subject = fields.get("subject", "")

    # ========================================================
    # STEP 1: AI vs HUMAN
    # ========================================================
    ai_label = predict_ai_human(email_text)

    if ai_label == "AI":
        is_ai_email = True

    # 🔥 SAVE AI DATASET
    try:
        add_to_ai_human_dataset(subject, email_text, sender_email, ai_label)
    except Exception as e:
        log.error(f"AI dataset save error: {e}")

    # ========================================================
    # BASE RESULT
    # ========================================================
    result = {
        "email": sender_email,
        "ai_generated": ai_label,
        "classification": "Unknown",
        "risk_score": 0,
        "confidence": 0,

        # OSINT
        "social_links": "",
        "social_links_list": [],
        "geolocation": "",
        "isp": "",

        # Domain
        "domain_age": "",
        "domain_registrar": "",
        "domain_created": "",

        # VirusTotal
        "vt_results": [],

        # Identity
        "person_detected": "NO",
        "best_profile": "",
        "person_name": "",
        "person_bio": "",
        "profile_image": "",

        # Final
        "anonymity": "",
        "analysis_time": ""
    }

    # ========================================================
    # 🚫 STOP IF AI GENERATED
    # ========================================================
    if is_ai_email:
        result["classification"] = "Safe"
        result["anonymity"] = "UNKNOWN (Machine generated)"
        result["analysis_time"] = round(time.time() - start_time, 2)
        return result

    # ========================================================
    # STEP 2: SAFE vs UNSAFE
    # ========================================================
    try:
        su = classify_safe_unsafe(subject, email_text, sender_email)

        result["classification"] = su["label"]
        result["risk_score"] = su["risk_score"]
        result["confidence"] = su["confidence"]
        result["signals"] = su["signals"]

        # 🔥 SAVE SAFE/UNSAFE DATASET
        add_to_safe_unsafe_dataset(subject, email_text, sender_email, su["label"])

    except Exception as e:
        log.error(f"Safety error: {e}")
        result["classification"] = "Safe"

    # ========================================================
    # STEP 3: OSINT (ONLY HUMAN EMAIL)
    # ========================================================
    domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    # ---------------- SOCIAL LINKS --------------------------
    try:
        from src.intelligence.social_lookup import find_social_links, format_social_links_text

        links = find_social_links(sender_email)

    except Exception as e:
        log.error(f"Social lookup error: {e}")
        links = []

    # ---------------- DOMAIN INFO ---------------------------
    try:
        from src.intelligence.domain_intel import get_domain_info

        domain_info = get_domain_info(domain)

        result["domain_age"] = domain_info.get("age", "")
        result["domain_registrar"] = domain_info.get("registrar", "")
        result["domain_created"] = domain_info.get("created", "")

    except Exception as e:
        log.error(f"Domain error: {e}")
        domain_info = {}

    # ---------------- IP + GEO ------------------------------
    geo = {}
    try:
        from src.forensic.ip_geolocation import get_geolocation

        ip_list = fields.get("ip_addresses", [])

        if ip_list:
            geo = get_geolocation(ip_list[0])
            result["geolocation"] = f"{geo.get('city')}, {geo.get('country')}"
            result["isp"] = geo.get("isp")

    except Exception as e:
        log.error(f"Geo error: {e}")

    # ========================================================
    # STEP 4: SOCIAL RANKING
    # ========================================================
    try:
        from src.intelligence.social_filter import rank_social_links

        ranked_links = rank_social_links(links, geo, domain_info)

        result["social_links_list"] = ranked_links
        result["social_links"] = format_social_links_text(ranked_links)

    except Exception as e:
        log.error(f"Ranking error: {e}")
        ranked_links = links

    # ========================================================
    # STEP 5: VIRUSTOTAL (ONLY IF UNSAFE)
    # ========================================================
    if result["classification"] == "Unsafe":

        try:
            from src.intelligence.virustotal import scan_url

            urls = fields.get("urls_found", [])
            vt_results = []

            for url in urls[:3]:
                vt = scan_url(url)
                vt_results.append(vt)

            result["vt_results"] = vt_results

        except Exception as e:
            log.error(f"VirusTotal error: {e}")

    # ========================================================
    # STEP 6: PROFILE SCRAPING
    # ========================================================
    try:
        from src.intelligence.profile_scraper import scrape_profile

        if ranked_links:

            best = ranked_links[0]

            if best.get("score", 0) > 40:

                profile_data = scrape_profile(best.get("url"))

                result["person_detected"] = "YES"
                result["best_profile"] = best.get("url")

                result["person_name"] = profile_data.get("name")
                result["person_bio"] = profile_data.get("bio")
                result["profile_image"] = profile_data.get("image")

                result["anonymity"] = "LOW (Person identified)"

            else:
                result["anonymity"] = "MEDIUM (Weak identity match)"

        else:
            result["person_detected"] = "NO"
            result["anonymity"] = "HIGH (Anonymous sender)"

    except Exception as e:
        log.error(f"Profile scraping error: {e}")
        result["anonymity"] = "UNKNOWN"

    # ========================================================
    # STEP 7: SAVE CSV
    # ========================================================
    try:
        from src.utils.save_csv import save_result
        save_result(result)
    except:
        pass

    # ========================================================
    # FINAL TIME
    # ========================================================
    result["analysis_time"] = round(time.time() - start_time, 2)

    return result