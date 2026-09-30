import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "confirm", "password", "credential", "signin", "banking", "wallet",
    "payment", "invoice", "recover", "unlock", "suspended", "bonus",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly",
}


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _has_punycode(hostname: str) -> bool:
    return any(part.lower().startswith("xn--") for part in hostname.split("."))


def _looks_like_url(text: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text))


def analyze_url(raw_url: str) -> dict:
    raw_url = raw_url.strip()

    if len(raw_url) > 2048:
        raise ValueError("URL is too long to analyze safely.")

    if not raw_url:
        raise ValueError("URL cannot be empty.")

    normalized_url = raw_url if _looks_like_url(raw_url) else f"https://{raw_url}"
    parsed = urlparse(normalized_url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("The URL does not contain a valid hostname.")

    path_and_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    full_lower = normalized_url.lower()

    suspicious_keywords = sorted(
        keyword for keyword in SUSPICIOUS_KEYWORDS
        if keyword in full_lower
    )

    subdomain_count = max(0, len(hostname.split(".")) - 2)
    digit_count = sum(char.isdigit() for char in hostname)
    special_count = sum(char in "-_@" for char in hostname)

    features = {
        "https": parsed.scheme == "https",
        "hostname": hostname,
        "domain_length": len(hostname),
        "url_length": len(normalized_url),
        "path_length": len(parsed.path),
        "subdomain_count": subdomain_count,
        "digit_count_in_host": digit_count,
        "special_characters_in_host": special_count,
        "contains_ip": _is_ip_address(hostname),
        "contains_punycode": _has_punycode(hostname),
        "contains_at_symbol": "@" in normalized_url,
        "has_query": bool(parsed.query),
        "query_parameter_count": len(parsed.query.split("&")) if parsed.query else 0,
        "suspicious_keyword_count": len(suspicious_keywords),
        "suspicious_keywords": suspicious_keywords,
        "is_url_shortener": hostname in SHORTENER_DOMAINS,
        "has_port": parsed.port is not None,
        "fragment_present": bool(parsed.fragment),
        "path_and_query": path_and_query,
    }

    return {
        "normalized_url": normalized_url,
        "features": features,
    }
