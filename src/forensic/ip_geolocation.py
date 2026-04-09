# ============================================================
# FILE: src/forensic/ip_geolocation.py
# ============================================================
import requests

_CACHE = {}

def get_geolocation(ip: str) -> dict:
    """
    Look up geolocation for a public IP using ip-api.com (free, no key needed).
    Returns dict: country, region, city, lat, lon, timezone, isp, org, as_number
    """
    if not ip or ip in _CACHE:
        return _CACHE.get(ip, _empty())
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"},
            timeout=5
        )
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "ip":          data.get("query", ip),
                "country":     data.get("country", ""),
                "country_code":data.get("countryCode", ""),
                "region":      data.get("regionName", ""),
                "city":        data.get("city", ""),
                "latitude":    data.get("lat", ""),
                "longitude":   data.get("lon", ""),
                "timezone":    data.get("timezone", ""),
                "isp":         data.get("isp", ""),
                "org":         data.get("org", ""),
                "as_number":   data.get("as", ""),
            }
            _CACHE[ip] = result
            return result
    except Exception:
        pass
    return _empty()

def get_geolocation_bulk(ips: list) -> list:
    return [get_geolocation(ip) for ip in ips]

def _empty() -> dict:
    return {
        "ip": "", "country": "", "country_code": "", "region": "",
        "city": "", "latitude": "", "longitude": "", "timezone": "",
        "isp": "", "org": "", "as_number": "",
    }