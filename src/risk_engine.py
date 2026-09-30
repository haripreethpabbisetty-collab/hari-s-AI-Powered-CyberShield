def calculate_risk(analysis: dict) -> dict:
    """
    Explainable first-generation risk engine.

    This is intentionally rule-based so the GitHub prototype works immediately.
    A future ML model can replace/augment this function without changing the API.
    """
    f = analysis["features"]
    score = 0
    signals = []

    def add(points, title, detail):
        nonlocal score
        score += points
        signals.append({
            "type": "warning" if points > 0 else "positive",
            "title": title,
            "detail": detail,
            "points": points,
        })

    if not f["https"]:
        add(18, "HTTPS is not enabled",
            "The connection uses HTTP instead of HTTPS.")
    else:
        add(0, "HTTPS is enabled",
            "The URL uses an encrypted HTTPS connection.")

    if f["contains_ip"]:
        add(25, "IP address used as hostname",
            "Using a raw IP address can be a phishing indicator.")

    if f["contains_at_symbol"]:
        add(28, "At-symbol detected",
            "An '@' in a URL can hide the actual destination.")

    if f["contains_punycode"]:
        add(20, "Punycode hostname detected",
            "Internationalized hostname encoding can be abused for look-alike domains.")

    if f["is_url_shortener"]:
        add(12, "URL shortener detected",
            "Shortened URLs hide the final destination until they are resolved.")

    if f["url_length"] > 120:
        add(10, "Unusually long URL",
            "Very long URLs can contain tracking or deceptive path/query data.")

    if f["subdomain_count"] >= 3:
        add(12, "Many subdomains",
            "The hostname contains an unusually deep subdomain structure.")

    if f["suspicious_keyword_count"] >= 2:
        add(18, "Multiple security-related keywords",
            ", ".join(f["suspicious_keywords"]) + " appear in the URL.")
    elif f["suspicious_keyword_count"] == 1:
        add(7, "Security-related keyword detected",
            f["suspicious_keywords"][0] + " appears in the URL.")

    if f["digit_count_in_host"] >= 5:
        add(8, "Many digits in hostname",
            "The hostname contains several numeric characters.")

    if f["special_characters_in_host"] >= 3:
        add(8, "Unusual hostname characters",
            "The hostname contains several special characters.")

    if f["query_parameter_count"] >= 6:
        add(6, "Many query parameters",
            "The URL contains many query parameters.")

    # Keep the score deterministic and bounded.
    score = min(100, score)

    if score >= 70:
        level = "HIGH RISK"
        summary = "Several indicators suggest this URL may be unsafe."
        recommendation = "Do not enter passwords, payment details, or other sensitive information."
    elif score >= 40:
        level = "SUSPICIOUS"
        summary = "The URL contains indicators that deserve additional verification."
        recommendation = "Verify the domain independently before interacting with the page."
    else:
        level = "LOW RISK"
        summary = "No strong phishing indicators were found by the current rule set."
        recommendation = "Still verify the website and sender before sharing sensitive information."

    # Add a neutral positive signal when there were no warnings.
    if not signals:
        signals.append({
            "type": "positive",
            "title": "No notable indicators",
            "detail": "The current analyzer did not identify a configured warning signal.",
            "points": 0,
        })

    return {
        "score": score,
        "level": level,
        "summary": summary,
        "signals": signals,
        "recommendation": recommendation,
    }
