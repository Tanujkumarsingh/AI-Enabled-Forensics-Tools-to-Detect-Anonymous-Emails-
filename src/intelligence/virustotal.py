# ============================================================
# FILE: src/intelligence/virustotal.py
# PASTE AS: src/intelligence/virustotal.py
# ============================================================
import os
import requests
import base64

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


def scan_url(url: str, api_key: str = VT_API_KEY) -> dict:
    """Submit a URL to VirusTotal and return detection stats."""
    if not api_key:
        return {"error": "No VirusTotal API key. Set VIRUSTOTAL_API_KEY env variable.",
                "malicious": 0, "harmless": 0, "suspicious": 0}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": api_key}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            data  = resp.json()
            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            return {
                "url":        url,
                "malicious":  stats.get("malicious",  0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless",   0),
                "undetected": stats.get("undetected", 0),
                "is_malicious": stats.get("malicious", 0) > 0,
            }
        if resp.status_code == 404:
            return {"url": url, "malicious": 0, "note": "URL not in VirusTotal database"}
    except Exception as e:
        return {"error": str(e), "malicious": 0}
    return {"error": "Request failed", "malicious": 0}


def scan_urls_bulk(urls: list, api_key: str = VT_API_KEY) -> list:
    return [scan_url(u, api_key) for u in urls]# ============================================================
# FILE: src/intelligence/virustotal.py
# PASTE AS: src/intelligence/virustotal.py
# ============================================================
import os
import requests
import base64

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


def scan_url(url: str, api_key: str = VT_API_KEY) -> dict:
    """Submit a URL to VirusTotal and return detection stats."""
    if not api_key:
        return {"error": "No VirusTotal API key. Set VIRUSTOTAL_API_KEY env variable.",
                "malicious": 0, "harmless": 0, "suspicious": 0}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": api_key}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            data  = resp.json()
            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            return {
                "url":        url,
                "malicious":  stats.get("malicious",  0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless",   0),
                "undetected": stats.get("undetected", 0),
                "is_malicious": stats.get("malicious", 0) > 0,
            }
        if resp.status_code == 404:
            return {"url": url, "malicious": 0, "note": "URL not in VirusTotal database"}
    except Exception as e:
        return {"error": str(e), "malicious": 0}
    return {"error": "Request failed", "malicious": 0}


def scan_urls_bulk(urls: list, api_key: str = VT_API_KEY) -> list:
    return [scan_url(u, api_key) for u in urls]