from pathlib import Path
import joblib


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "phishing_url_model.joblib"

_model = None


def load_model():
    global _model

    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                "ML model not found. Run: python ml\\train_model.py"
            )

        _model = joblib.load(MODEL_PATH)

    return _model


def predict_url(url: str) -> dict:
    model = load_model()

    prediction = int(model.predict([url])[0])

    probabilities = model.predict_proba([url])[0]

    phishing_probability = float(probabilities[1])
    legitimate_probability = float(probabilities[0])

    if prediction == 1:
        label = "PHISHING"
    else:
        label = "LEGITIMATE"

    return {
        "prediction": label,
        "phishing_probability": round(phishing_probability * 100, 2),
        "legitimate_probability": round(legitimate_probability * 100, 2),
    }