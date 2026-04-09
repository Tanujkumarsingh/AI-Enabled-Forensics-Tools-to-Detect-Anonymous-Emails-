# ============================================================
# FILE: src/intelligence/ip_intel.py
# ============================================================
import requests

_CACHE = {}

def get_ip_intel(ip: str) -> dict:
    """
    Get ASN, ISP, org, hosting provider for an IP.
    Uses ip-api.com (free) + ipinfo.io fallback.
    """
    if not ip or ip in _CACHE:
        return _CACHE.get(ip, {})
    result = {}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,isp,org,as,hosting,proxy,query"},
            timeout=5
        )
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "ip":       data.get("query", ip),
                "isp":      data.get("isp", ""),
                "org":      data.get("org", ""),
                "as":       data.get("as", ""),
                "hosting":  data.get("hosting", False),
                "proxy":    data.get("proxy", False),
            }
    except Exception:
        pass

    if not result:
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            data = resp.json()
            result = {
                "ip":    data.get("ip", ip),
                "isp":   data.get("org", ""),
                "org":   data.get("org", ""),
                "as":    data.get("org", ""),
                "hosting": False,
                "proxy": False,
            }
        except Exception:
            pass

    _CACHE[ip] = result
    return result