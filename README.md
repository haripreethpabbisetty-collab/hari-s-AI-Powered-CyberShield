# 🛡️ AI-Powered CyberShield

### Real-Time Phishing and Threat Detection

CyberShield is a cybersecurity research prototype that analyzes URLs and
produces an explainable risk assessment using security-oriented URL features.

The repository is intentionally modular so that the first working version can
later be extended with machine learning, NLP, computer vision, and
Snapdragon/edge-AI inference.

## ✨ Current Features

- URL normalization
- HTTPS detection
- IP-address hostname detection
- Punycode detection
- suspicious keyword detection
- URL length analysis
- subdomain analysis
- URL shortener detection
- query-parameter analysis
- explainable risk scoring
- browser-based cybersecurity dashboard
- JSON API
- responsive UI

## 🧠 Current Architecture

```text
Browser
   │
   ▼
Flask API
   │
   ▼
CyberShield Detector
   │
   ├── URL Feature Analyzer
   │
   └── Explainable Risk Engine
            │
            ▼
       Risk Score + Signals
```

## 🚀 Run on Windows

### 1. Install Python

Install Python 3.11 or newer and make sure Python is available from the
Windows terminal.

Check:

```powershell
python --version
```

### 2. Create a virtual environment

From the project root:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then activate again.

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Start CyberShield

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## 🔌 API

### POST `/api/scan`

Example JSON:

```json
{
  "url": "https://example.com"
}
```

The API returns:

```json
{
  "risk_score": 0,
  "risk_level": "LOW RISK",
  "signals": [],
  "recommendation": "..."
}
```

## ⚠️ Important

A low-risk result does NOT prove that a website is safe. The current engine
is a research prototype and does not perform live domain reputation checks,
sandboxing, malware analysis, DNS intelligence, or webpage inspection.

Do not use this prototype as the sole security control.

## 🔬 Planned Research Roadmap

### Phase 1
Explainable URL analysis — current version.

### Phase 2
Train and evaluate a phishing URL classifier.

### Phase 3
Add NLP analysis for suspicious messages/emails.

### Phase 4
Add webpage screenshot analysis using computer vision.

### Phase 5
Fuse URL, NLP, and vision signals.

### Phase 6
Optimize inference for supported Snapdragon/edge-AI hardware.

### Phase 7
Benchmark accuracy, latency, memory usage, and power consumption.

## 📁 Project Structure

```text
AI-Powered-CyberShield/
├── app.py
├── detector.py
├── requirements.txt
├── README.md
├── src/
│   ├── __init__.py
│   ├── url_analyzer.py
│   └── risk_engine.py
├── data/
│   └── README.md
├── models/
│   └── README.md
├── static/
│   ├── style.css
│   └── script.js
└── templates/
    └── index.html
```

## 👨‍💻 Project Status

Prototype / research project.

The project is designed to evolve from explainable URL analysis into a
privacy-preserving edge-AI cybersecurity system.
