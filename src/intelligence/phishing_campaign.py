# ============================================================
# FILE: src/intelligence/phishing_campaign.py
# PASTE AS: src/intelligence/phishing_campaign.py
# ============================================================
import re

CAMPAIGN_PATTERNS = [
    # Account verification
    (r"verify.{0,20}(account|email|identity|information)",
     "Account verification phishing"),
    (r"(confirm|validate|reactivate).{0,20}(account|profile|email)",
     "Account validation phishing"),

    # Urgency / threat
    (r"(urgent|immediate|action required).{0,50}(account|password|access|payment)",
     "Urgency phishing"),
    (r"(suspended|locked|limited|blocked).{0,30}account",
     "Account suspension threat"),
    (r"(account|access).{0,20}(will be|has been).{0,20}(closed|suspended|terminated)",
     "Account termination threat"),

    # Prize / lottery
    (r"(lottery|won|winner|prize|reward).{0,30}(claim|collect|redeem|selected)",
     "Lottery / prize scam"),
    (r"(congratulations|selected).{0,30}(winner|recipient|lucky)",
     "Winner notification scam"),
    (r"you.{0,10}(have won|are the winner|been selected).{0,30}(prize|cash|reward|million)",
     "Prize winner scam"),

    # Advance fee / 419
    (r"(inherit|beneficiary|million|funds|transfer).{0,40}(bank|account|help|assist)",
     "Advance fee fraud (419 scam)"),
    (r"(dying|ill|cancer|disease).{0,40}(funds|million|transfer|donate)",
     "Dying person funds scam"),

    # Invoice / payment fraud
    (r"(invoice|payment|bill).{0,30}(overdue|pending|due|attached|outstanding)",
     "Invoice fraud"),
    (r"(outstanding|unpaid).{0,20}(balance|amount|invoice|payment)",
     "Unpaid balance threat"),

    # Tech support scam
    (r"(virus|malware|hacked|compromised).{0,30}(computer|device|account|detected)",
     "Tech support / malware scam"),
    (r"(microsoft|apple|google).{0,20}(support|security|team).{0,20}(detected|found|alert)",
     "Fake tech support scam"),

    # Brand impersonation
    (r"(paypal|amazon|netflix|apple|microsoft|google|facebook).{0,30}"
     r"(account|verify|confirm|security|update|suspend)",
     "Brand impersonation phishing"),

    # Delivery scam
    (r"(package|parcel|delivery|shipment).{0,30}(failed|held|pending|re-?schedule)",
     "Fake delivery notification scam"),
    (r"(fedex|ups|dhl|usps|royal mail).{0,30}(delivery|package|tracking)",
     "Delivery courier impersonation"),

    # Gift card / free product
    (r"(free|complimentary|win).{0,20}(iphone|ipad|laptop|samsung|gift card)",
     "Fake product giveaway"),
    (r"(pay|cover).{0,15}(shipping|handling|delivery).{0,15}(fee|cost|charge)",
     "Pay-shipping-only scam"),

    # Generic mass phishing
    (r"(dear|hello).{0,10}(customer|user|member|friend|sir|madam)",
     "Generic mass phishing"),
]


def detect_campaign(body: str, subject: str = "") -> dict:
    """
    Detect phishing campaign type from email body and subject.
    Returns { is_phishing, detected: [list of campaign names], count }
    """
    text    = (subject + " " + body).lower()
    found   = []

    for pattern, label in CAMPAIGN_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            if label not in found:
                found.append(label)

    return {
        "is_phishing": len(found) > 0,
        "detected":    found,
        "count":       len(found),
    }