# ============================================================
# FILE: src/forensic/url_analyzer.py
# ============================================================
import re
import requests

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update", "confirm",
    "click", "free", "prize", "winner", "bank", "paypal", "urgent",
    "reset", "password", "credential", "validate", "suspend",
    "invoice", "payment", "billing", "alert", "warning", "verify",
    "sign-in", "signin", "webscr", "cmd=", "ebayisapi",
]

def extract_urls(text: str) -> list:
    """Extract all URLs from text."""
    return list(set(re.findall(r"https?://[^\s<>\"']+", text)))

def analyze_urls(urls: list) -> dict:
    """Analyse a list of URLs for suspicious indicators."""
    suspicious = []
    ip_based   = []
    shorteners = []
    clean      = []

    SHORT_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                     "short.io", "rebrand.ly", "tiny.cc", "is.gd", "buff.ly"}

    for url in urls:
        lower = url.lower()
        flagged = False

        # IP-based URL
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            ip_based.append(url)
            flagged = True

        # Keyword match
        if any(kw in lower for kw in SUSPICIOUS_KEYWORDS):
            suspicious.append(url)
            flagged = True

        # URL shortener
        domain = re.search(r"https?://([^/]+)", url)
        if domain and domain.group(1).lower() in SHORT_DOMAINS:
            shorteners.append(url)
            flagged = True

        if not flagged:
            clean.append(url)

    return {
        "total":        len(urls),
        "suspicious":   suspicious,
        "ip_based":     ip_based,
        "shorteners":   shorteners,
        "clean":        clean,
        "risk":         len(suspicious) + len(ip_based) * 2 + len(shorteners),
    }

def check_url_virustotal(url: str, api_key: str) -> dict:
    """Submit URL to VirusTotal for scanning."""
    if not api_key:
        return {"error": "No API key"}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": api_key}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "clean": stats.get("harmless", 0)}
    except Exception as e:
        return {"error": str(e)}
    return {}