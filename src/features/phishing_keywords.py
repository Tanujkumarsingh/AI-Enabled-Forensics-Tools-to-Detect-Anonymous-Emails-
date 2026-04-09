# ============================================================
# FILE: src/features/phishing_keywords.py
# PASTE AS: src/features/phishing_keywords.py
# ============================================================

PHISHING_KEYWORDS = {
    "critical": [
        # Account threats
        "verify your account", "confirm your identity",
        "your account has been suspended", "account will be closed",
        "account has been limited", "account has been locked",
        "your account will be permanently suspended",
        "login to avoid suspension", "unauthorized access detected",
        "unusual activity detected", "account locked",
        "verify now", "your account will be permanently closed",
        # Financial
        "bank account details", "social security number",
        "credit card number", "enter your password",
        "update your payment information", "billing information required",
        "confirm your credit card", "your card has been declined",
        "payment method required", "payment details expired",
        # Prize / lottery scam
        "you have won", "you've been selected as the winner",
        "claim your prize", "claim your reward", "claim your winnings",
        "lottery winner", "you are the lucky winner",
        "you have been selected", "selected as our winner",
        "one million dollars", "one million usd", "$1,000,000",
        "processing fee required", "send your full name and address",
        "wire transfer required", "western union",
        # Advance fee fraud
        "inheritance funds", "beneficiary", "transfer of funds",
        "million dollars in my bank", "dying and need your help",
        # Credential phishing
        "click here immediately", "verify now", "confirm now",
    ],
    "high": [
        "dear customer", "dear user", "dear valued member",
        "dear valued customer", "dear account holder",
        "congratulations you", "congratulations dear",
        "you have been randomly selected", "randomly selected to receive",
        "free iphone", "free gift", "free reward",
        "urgent action required", "response required immediately",
        "immediate action required", "act now",
        "confirm email address", "reset your password",
        "suspicious login attempt", "suspicious activity",
        "reactivate your account", "validate your account",
        "suspended account", "account termination",
        "limited time offer expires", "offer expires in",
        "only 24 hours", "within 48 hours", "expires soon",
        "last chance", "final notice", "final warning",
        "your package is on hold", "delivery failed",
        "your parcel could not be delivered",
        "you owe", "outstanding balance", "overdue payment",
        "pay now to avoid", "failure to pay",
        "irs tax refund", "income tax refund",
        "you are owed a refund", "tax return pending",
        "verify your paypal", "verify your amazon",
        "amazon account suspended", "paypal account limited",
    ],
    "medium": [
        "click here", "click below", "click the link",
        "follow this link", "visit our website",
        "free offer", "limited time", "limited offer",
        "special promotion", "100% free", "no cost to you",
        "earn money fast", "make money online", "work from home",
        "guaranteed results", "risk free", "no obligation",
        "limited spots available", "hurry", "act fast",
        "do not ignore", "do not miss", "do not delay",
        "update now", "confirm now", "respond immediately",
        "only for you", "exclusive offer", "you are chosen",
        "pay only shipping", "just pay shipping",
        "enter your details", "provide your information",
    ],
    "low": [
        "unsubscribe", "opt out", "this is not spam",
        "you are receiving this email", "do not reply",
        "auto-generated email", "noreply",
        "this email was sent to", "remove from list",
        "manage your email preferences",
    ],
}

SCORE_MAP = {"critical": 30, "high": 15, "medium": 8, "low": 2}


def score_keywords(text: str) -> dict:
    """
    Score email text based on phishing keyword matches.
    Returns { score (0-100), matches, count }
    """
    text_lower = text.lower()
    matches    = {}
    total      = 0

    for level, keywords in PHISHING_KEYWORDS.items():
        found = [kw for kw in keywords if kw in text_lower]
        if found:
            matches[level] = found
            total += SCORE_MAP[level] * len(found)

    return {
        "score":   min(total, 100),
        "matches": matches,
        "count":   sum(len(v) for v in matches.values()),
    }


def get_all_keywords() -> list:
    result = []
    for keywords in PHISHING_KEYWORDS.values():
        result.extend(keywords)
    return result