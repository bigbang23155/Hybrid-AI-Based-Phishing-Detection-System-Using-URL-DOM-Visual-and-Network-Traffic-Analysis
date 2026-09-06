"""Deterministic lexical features calculated only from a URL string."""

from __future__ import annotations

from collections import Counter
import ipaddress
import math
from urllib.parse import urlsplit

from .url_cleaning import clean_url, subdomain_count

SUSPICIOUS_KEYWORDS = (
    "account", "bank", "confirm", "login", "password", "secure", "signin", "update", "verify"
)

FEATURE_NAMES = (
    "url_length", "hostname_length", "path_length", "query_length", "dot_count",
    "subdomain_count", "slash_count", "digit_count", "digit_ratio", "hyphen_count",
    "at_count", "question_count", "equals_count", "ampersand_count", "uses_https",
    "is_ip_hostname", "suspicious_keyword_count", "url_entropy",
)
BINARY_FEATURES = frozenset(("uses_https", "is_ip_hostname"))
FLOAT_FEATURES = frozenset(("digit_ratio", "url_entropy"))


def _entropy(text: str) -> float:
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in Counter(text).values())


def extract_features(url: str) -> dict[str, int | float]:
    """Clean *url* and return the documented fixed URL-only feature dictionary."""
    cleaned = clean_url(url)
    parts = urlsplit(cleaned)
    hostname = parts.hostname or ""
    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
        subdomains = 0
    except ValueError:
        is_ip = 0
        subdomains = subdomain_count(cleaned)

    digits = sum(character.isdecimal() for character in cleaned)
    lowered = cleaned.lower()
    return {
        "url_length": len(cleaned),
        "hostname_length": len(hostname),
        "path_length": len(parts.path),
        "query_length": len(parts.query),
        "dot_count": cleaned.count("."),
        "subdomain_count": subdomains,
        "slash_count": cleaned.count("/"),
        "digit_count": digits,
        "digit_ratio": digits / len(cleaned),
        "hyphen_count": cleaned.count("-"),
        "at_count": cleaned.count("@"),
        "question_count": cleaned.count("?"),
        "equals_count": cleaned.count("="),
        "ampersand_count": cleaned.count("&"),
        "uses_https": int(parts.scheme == "https"),
        "is_ip_hostname": is_ip,
        "suspicious_keyword_count": sum(lowered.count(word) for word in SUSPICIOUS_KEYWORDS),
        "url_entropy": _entropy(cleaned),
    }
