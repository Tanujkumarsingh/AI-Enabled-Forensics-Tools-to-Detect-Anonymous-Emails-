# ============================================================
# FILE: src/forensic/spf_dkim_checker.py
# ============================================================
import dns.resolver

def check_spf_dkim(domain: str) -> dict:
    """
    Check SPF and DKIM DNS records for a sender domain.
    Returns { spf, dkim, spf_record, dkim_record }
    """
    result = {"spf": "unknown", "dkim": "unknown", "spf_record": "", "dkim_record": ""}
    if not domain:
        return result

    # ── SPF ────────────────────────────────────────────────
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join(str(s) for s in rdata.strings if isinstance(s, (str, bytes)))
            if isinstance(txt, bytes):
                txt = txt.decode("utf-8", errors="replace")
            if "v=spf1" in txt.lower():
                result["spf_record"] = txt
                result["spf"] = "pass" if ("include" in txt or "ip4" in txt or "ip6" in txt or "a" in txt) else "neutral"
                break
        else:
            result["spf"] = "none"
    except Exception:
        result["spf"] = "error"

    # ── DKIM ───────────────────────────────────────────────
    selectors = ["default", "google", "mail", "dkim", "k1", "s1", "s2"]
    for sel in selectors:
        try:
            dkim_domain = f"{sel}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, "TXT", lifetime=5)
            for rdata in answers:
                txt = "".join(str(s) for s in rdata.strings)
                if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                    result["dkim_record"] = txt[:200]
                    result["dkim"] = "pass"
                    break
            if result["dkim"] == "pass":
                break
        except Exception:
            continue
    if result["dkim"] == "unknown":
        result["dkim"] = "none"

    return result