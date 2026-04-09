import requests
from bs4 import BeautifulSoup


def scrape_profile(url):

    result = {
        "name": "",
        "bio": "",
        "image": "",
        "location": ""
    }

    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        res = requests.get(url, headers=headers, timeout=5)

        soup = BeautifulSoup(res.text, "html.parser")

        # 🔹 NAME (generic)
        title = soup.find("title")
        if title:
            result["name"] = title.text.strip()

        # 🔹 IMAGE (common meta tags)
        img = soup.find("meta", property="og:image")
        if img:
            result["image"] = img.get("content")

        # 🔹 DESCRIPTION
        desc = soup.find("meta", property="og:description")
        if desc:
            result["bio"] = desc.get("content")

    except Exception:
        pass

    return result