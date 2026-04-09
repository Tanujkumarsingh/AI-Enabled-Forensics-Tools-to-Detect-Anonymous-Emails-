# ============================================================
# FILE: src/intelligence/domain_intel.py
# ============================================================
import datetime

def get_domain_info(domain: str) -> dict:
    """
    WHOIS lookup for a domain: age, registrar, creation date, expiry.
    """
    result = {
        "domain":     domain,
        "registrar":  "",
        "created":    "",
        "expires":    "",
        "updated":    "",
        "age":        "",
        "name_servers": [],
        "status":     [],
    }
    if not domain:
        return result
    try:
        import whois
        w = whois.whois(domain)
        result["registrar"]    = str(w.registrar or "")
        result["name_servers"] = list(w.name_servers or [])
        result["status"]       = [str(w.status)] if isinstance(w.status, str) else [str(s) for s in (w.status or [])]

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            result["created"] = str(created)
            try:
                age_days = (datetime.datetime.utcnow() - created.replace(tzinfo=None)).days
                years    = age_days // 365
                months   = (age_days % 365) // 30
                result["age"] = f"{years} yr {months} mo" if years else f"{months} mo"
            except Exception:
                pass

        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        if expires:
            result["expires"] = str(expires)

        updated = w.updated_date
        if isinstance(updated, list):
            updated = updated[0]
        if updated:
            result["updated"] = str(updated)

    except Exception:
        pass
    return result