import re


def normalize(text):
    return str(text).lower().strip() if text else ""


def extract_username(email):
    if not email or "@" not in email:
        return ""
    return email.split("@")[0]


def score_profile(link, geo, domain_info, email=""):
    score = 0
    url = normalize(link.get("url"))

    country = normalize(geo.get("country"))
    region = normalize(geo.get("region"))
    city = normalize(geo.get("city"))
    registrar = normalize(domain_info.get("registrar"))
    username = normalize(extract_username(email))

    # 🔥 USERNAME MATCH (VERY IMPORTANT)
    if username and username in url:
        score += 60

    # 🌍 GEO MATCH
    if country and country in url:
        score += 30
    if region and region in url:
        score += 20
    if city and city in url:
        score += 15

    # 🏢 DOMAIN / ORG MATCH
    if registrar and registrar in url:
        score += 20

    # 🌐 PLATFORM PRIORITY
    if "linkedin.com" in url:
        score += 70
    elif "github.com" in url:
        score += 60
    elif "twitter.com" in url or "x.com" in url:
        score += 50
    elif "instagram.com" in url:
        score += 40
    elif "facebook.com" in url:
        score += 35

    # 🎓 EDUCATION BOOST
    edu_keywords = ["iit", "nit", "iiit", "university", "college", "phd"]
    for kw in edu_keywords:
        if kw in url:
            score += 10

    # 🚫 PENALTY (SEARCH PAGES)
    if "search" in url or "google.com" in url:
        score -= 10

    return score


def rank_social_links(links, geo, domain_info, email=""):
    ranked = []

    for link in links:
        score = score_profile(link, geo, domain_info, email)

        if score > 20:  # filter weak links
            link["score"] = score
            ranked.append(link)

    ranked.sort(key=lambda x: x["score"], reverse=True)

    return ranked[:15]