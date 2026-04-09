# ============================================================
# FILE: src/forensic/mail_server_detector.py
# ============================================================
import re
import dns.resolver

KNOWN_PROVIDERS = {
    "google.com": "Gmail / Google Workspace",
    "googlemail.com": "Gmail",
    "outlook.com": "Microsoft Outlook",
    "hotmail.com": "Microsoft Hotmail",
    "yahoo.com": "Yahoo Mail",
    "protonmail.com": "ProtonMail (encrypted)",
    "proton.me": "ProtonMail (encrypted)",
    "tutanota.com": "Tutanota (encrypted)",
    "zoho.com": "Zoho Mail",
    "fastmail.com": "FastMail",
    "icloud.com": "Apple iCloud Mail",
    "yandex.com": "Yandex Mail",
    "mailchimp.com": "Mailchimp (marketing)",
    "sendgrid.net": "SendGrid (marketing)",
    "amazonses.com": "Amazon SES",
}

def detect_mail_server(domain: str) -> dict:
    """Detect the mail server / provider for a given domain."""
    result = {"provider": "Unknown", "mx_records": [], "server_type": "unknown"}
    if not domain:
        return result

    # Check known providers
    for known, label in KNOWN_PROVIDERS.items():
        if domain.lower().endswith(known):
            result["provider"] = label
            result["server_type"] = "known"

    # MX lookup
    try:
        mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_list = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in mx_records],
            key=lambda x: x[0]
        )
        result["mx_records"] = [f"{pref} {exch}" for pref, exch in mx_list]

        # Infer provider from MX
        if mx_list:
            primary_mx = mx_list[0][1].lower()
            for known, label in KNOWN_PROVIDERS.items():
                if known.replace(".com", "") in primary_mx:
                    result["provider"] = label
                    result["server_type"] = "known"
                    break
    except Exception:
        pass

    return result