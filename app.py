from flask import Flask, render_template, request, jsonify
from detector import CyberShieldDetector

app = Flask(__name__)
detector = CyberShieldDetector()


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/api/scan")
def scan_url():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    try:
        result = detector.scan(url)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Unexpected scan error")
        return jsonify({"error": "The scanner could not process this URL."}), 500


if __name__ == "__main__":
    # Development server. Do not expose this directly to the public internet.
    app.run(host="127.0.0.1", port=5000, debug=True)
