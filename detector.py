from src.url_analyzer import analyze_url
from src.risk_engine import calculate_risk
from ml.predict import predict_url


class CyberShieldDetector:
    """Main application service for URL threat analysis."""

    def scan(self, url: str) -> dict:
        analysis = analyze_url(url)
        risk = calculate_risk(analysis)

        # Run the machine-learning model.
        ml_result = predict_url(analysis["normalized_url"])

        # Combine rule-based and ML analysis.
        rule_score = risk["score"]
        ml_score = ml_result["phishing_probability"]

        combined_score = round(
            (rule_score * 0.45) + (ml_score * 0.55)
        )

        if combined_score >= 70:
            final_level = "HIGH RISK"
        elif combined_score >= 40:
            final_level = "SUSPICIOUS"
        else:
            final_level = "LOW RISK"

        if final_level == "HIGH RISK":
            recommendation = (
                "Do not open this URL or provide credentials. "
                "The combined analysis indicates a high phishing risk."
            )
        elif final_level == "SUSPICIOUS":
            recommendation = (
                "Proceed carefully. Verify the website independently "
                "before entering credentials or payment information."
            )
        else:
            recommendation = (
                "No strong phishing indicators were detected. "
                "Continue using normal security precautions."
            )

        return {
            "url": analysis["normalized_url"],
            "risk_score": combined_score,
            "risk_level": final_level,
            "summary": (
                f"CyberShield combined rule-based and ML analysis. "
                f"ML classification: {ml_result['prediction']}."
            ),
            "signals": risk["signals"],
            "features": analysis["features"],
            "recommendation": recommendation,

            "ml": {
                "prediction": ml_result["prediction"],
                "phishing_probability": ml_result["phishing_probability"],
                "legitimate_probability": ml_result["legitimate_probability"],
            },

            "analysis": {
                "rule_score": rule_score,
                "ml_score": ml_score,
            },
        }