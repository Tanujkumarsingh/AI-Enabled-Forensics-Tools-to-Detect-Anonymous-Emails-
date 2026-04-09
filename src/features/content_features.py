# ============================================================
# FILE: src/features/content_features.py
# PASTE AS: src/features/content_features.py
# ============================================================
"""
NLP-style content feature extraction from email subject and body.
Used by the ensemble model and risk scoring engine.
"""

import re
import math
from collections import Counter


def extract_content_features(subject: str, body: str) -> dict:
    """
    Extract numerical content features from email text.
    Returns a flat dict of feature name → value.
    """
    text       = (subject + " " + body).strip()
    text_lower = text.lower()
    words      = re.findall(r"\b[a-z]+\b", text_lower)
    sentences  = [s.strip() for s in re.split(r"[.!?]+", body) if s.strip()]

    # ── Basic counts ─────────────────────────────────────────
    word_count      = len(words)
    sentence_count  = len(sentences) or 1
    unique_words    = len(set(words))
    char_count      = len(text)

    # ── HTML ─────────────────────────────────────────────────
    html_tags       = len(re.findall(r"<[^>]+>", body))
    html_links      = len(re.findall(r"<a\s+[^>]*href", body, re.IGNORECASE))

    # ── URLs ─────────────────────────────────────────────────
    url_count       = len(re.findall(r"https?://", body))
    ip_url_count    = len(re.findall(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", body))

    # ── Punctuation / Style ───────────────────────────────────
    exclamation     = body.count("!")
    question        = body.count("?")
    caps_words      = len(re.findall(r"\b[A-Z]{2,}\b", body))
    caps_ratio      = caps_words / max(word_count, 1)
    dollar_signs    = body.count("$")
    percent_signs   = body.count("%")

    # ── Avg sentence / word length ────────────────────────────
    avg_sent_len    = word_count / sentence_count
    avg_word_len    = sum(len(w) for w in words) / max(word_count, 1)

    # ── Vocabulary richness ───────────────────────────────────
    vocab_richness  = unique_words / max(word_count, 1)

    # ── Subject features ─────────────────────────────────────
    subj_len        = len(subject)
    subj_caps       = len(re.findall(r"\b[A-Z]{2,}\b", subject))
    subj_exclaim    = subject.count("!")
    subj_has_re     = 1 if re.match(r"^re:", subject.lower()) else 0
    subj_has_fwd    = 1 if re.match(r"^fwd:", subject.lower()) else 0

    # ── Entropy ──────────────────────────────────────────────
    freq  = Counter(words)
    total = len(words) or 1
    entropy = -sum((c / total) * math.log2(c / total) for c in freq.values()) if words else 0

    return {
        "word_count":        word_count,
        "sentence_count":    sentence_count,
        "unique_words":      unique_words,
        "char_count":        char_count,
        "avg_sentence_len":  round(avg_sent_len, 2),
        "avg_word_len":      round(avg_word_len, 2),
        "vocab_richness":    round(vocab_richness, 3),
        "text_entropy":      round(entropy, 3),
        "html_tag_count":    html_tags,
        "html_link_count":   html_links,
        "has_html":          html_tags > 0,
        "url_count":         url_count,
        "ip_url_count":      ip_url_count,
        "exclamation_count": exclamation,
        "question_count":    question,
        "caps_word_count":   caps_words,
        "caps_ratio":        round(caps_ratio, 3),
        "dollar_signs":      dollar_signs,
        "percent_signs":     percent_signs,
        "subject_length":    subj_len,
        "subject_caps":      subj_caps,
        "subject_exclaim":   subj_exclaim,
        "subject_is_reply":  subj_has_re,
        "subject_is_fwd":    subj_has_fwd,
        "body_length":       len(body),
    }