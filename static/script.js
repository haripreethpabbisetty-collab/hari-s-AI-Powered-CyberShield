const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");

const results = document.getElementById("results");
const errorMessage = document.getElementById("errorMessage");

const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");
const summary = document.getElementById("summary");

const mlPrediction = document.getElementById("mlPrediction");
const phishingProbability =
    document.getElementById("phishingProbability");

const legitimateProbability =
    document.getElementById("legitimateProbability");

const ruleScore = document.getElementById("ruleScore");

const signals = document.getElementById("signals");
const recommendation =
    document.getElementById("recommendation");

const features = document.getElementById("features");
const scoreRing = document.getElementById("scoreRing");


function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


async function scanURL() {

    const url = urlInput.value.trim();

    errorMessage.textContent = "";

    if (!url) {

        errorMessage.textContent =
            "Please enter a URL.";

        return;
    }


    scanButton.disabled = true;
    scanButton.textContent = "ANALYZING...";


    try {

        const response = await fetch("/api/scan", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error || "Scan failed."
            );

        }


        results.classList.remove("hidden");


        // Risk
        riskScore.textContent = data.risk_score;

        riskLevel.textContent =
            data.risk_level;

        summary.textContent =
            data.summary;


        // ML analysis
        if (data.ml) {

            mlPrediction.textContent =
                data.ml.prediction;

            phishingProbability.textContent =
                `${data.ml.phishing_probability}%`;

            legitimateProbability.textContent =
                `${data.ml.legitimate_probability}%`;

        }


        // Rule score
        if (data.analysis) {

            ruleScore.textContent =
                `${data.analysis.rule_score}/100`;

        }


        // Signals
        signals.innerHTML = "";

        data.signals.forEach(signal => {

            const li =
                document.createElement("li");

            li.textContent = signal;

            signals.appendChild(li);

        });


        // Recommendation
        recommendation.textContent =
            data.recommendation;


        // Features
        features.innerHTML = "";

        Object.entries(data.features).forEach(
            ([key, value]) => {

                const item =
                    document.createElement("div");

                item.className = "feature";

                item.innerHTML = `
                    <span>${escapeHtml(key)}</span>
                    <strong>${escapeHtml(value)}</strong>
                `;

                features.appendChild(item);

            }
        );


        // Risk styling
        scoreRing.classList.remove(
            "low",
            "medium",
            "high"
        );


        if (data.risk_score >= 70) {

            scoreRing.classList.add("high");

        } else if (data.risk_score >= 40) {

            scoreRing.classList.add("medium");

        } else {

            scoreRing.classList.add("low");

        }


    } catch (error) {

        errorMessage.textContent =
            error.message;

    } finally {

        scanButton.disabled = false;

        scanButton.textContent =
            "SCAN URL";

    }

}


scanButton.addEventListener(
    "click",
    scanURL
);


urlInput.addEventListener(
    "keydown",
    event => {

        if (event.key === "Enter") {

            scanURL();

        }

    }
);