from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

# Small starter dataset.
# label: 0 = legitimate, 1 = phishing
DATA = [
    ("https://www.google.com", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.apple.com", 0),
    ("https://www.amazon.com", 0),
    ("https://github.com", 0),
    ("https://www.linkedin.com", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.python.org", 0),
    ("https://www.cloudflare.com", 0),
    ("https://www.mozilla.org", 0),

    ("http://secure-login-verify-account.example.com", 1),
    ("http://verify-your-account.example.com/login", 1),
    ("http://paypal-security-check.example.com", 1),
    ("http://account-verification-login.example.com", 1),
    ("http://banking-secure-update.example.com", 1),
    ("http://password-reset-confirm.example.com", 1),
    ("http://wallet-security-verification.example.com", 1),
    ("http://login-confirm-account.example.com", 1),
    ("http://free-prize-bonus-claim.example.com", 1),
    ("http://suspended-account-recovery.example.com", 1),
]

df = pd.DataFrame(DATA, columns=["url", "label"])

X_train, X_test, y_train, y_test = train_test_split(
    df["url"],
    df["label"],
    test_size=0.25,
    random_state=42,
    stratify=df["label"],
)

model = Pipeline(
    [
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(2, 5),
                lowercase=True,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
            ),
        ),
    ]
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\n=== CyberShield ML Model Evaluation ===\n")
print(classification_report(
    y_test,
    predictions,
    target_names=["Legitimate", "Phishing"],
    zero_division=0,
))

model_path = MODEL_DIR / "phishing_url_model.joblib"
joblib.dump(model, model_path)

print(f"\nModel saved to:")
print(model_path)