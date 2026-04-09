# ============================================================
# FILE: src/forensic/anonymous_provider_detector.py
# ============================================================

ANONYMOUS_PROVIDERS = {
    # Temp / disposable
    "mailinator.com":       "Disposable email service",
    "guerrillamail.com":    "Disposable email service",
    "10minutemail.com":     "10-minute temp email",
    "tempmail.com":         "Disposable email service",
    "throwaway.email":      "Throwaway email",
    "yopmail.com":          "Disposable email service",
    "sharklasers.com":      "Guerrilla Mail alias",
    "trashmail.com":        "Trash email service",
    "dispostable.com":      "Disposable email",
    "maildrop.cc":          "Disposable email",
    "fakeinbox.com":        "Fake inbox service",
    "spamgourmet.com":      "Disposable email",
    "mailnull.com":         "Anonymous mail service",
    "trashmail.me":         "Trash email service",
    "getairmail.com":       "Disposable email",
    "discard.email":        "Discard email service",
    "tempr.email":          "Temp email service",
    "anonaddy.com":         "Anonymous email forwarding",
    "simplelogin.io":       "Anonymous email alias",
    # Privacy-focused
    "protonmail.com":       "Encrypted/anonymous provider (ProtonMail)",
    "proton.me":            "Encrypted/anonymous provider (ProtonMail)",
    "tutanota.com":         "Encrypted/anonymous provider (Tutanota)",
    "tutamail.com":         "Encrypted/anonymous provider (Tutanota)",
    "cock.li":              "Anonymous email provider",
    "secmail.pro":          "Disposable secure email",
    "dnmx.org":             "Anonymous email provider",
}

def detect_anonymous(domain: str) -> str:
    """
    Check if sender domain is a known anonymous/temp mail provider.
    Returns provider description string if found, empty string otherwise.
    """
    return ANONYMOUS_PROVIDERS.get(domain.lower().strip(), "")

def is_anonymous_provider(domain: str) -> bool:
    return domain.lower().strip() in ANONYMOUS_PROVIDERS