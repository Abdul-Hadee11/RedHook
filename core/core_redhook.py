from core.feature_extractor import extract_features
from core.url_checker import scan_urls
from core.tactic_analyzer import detect_tactics
from core.explain import generate_explanation
from core.db_manager import save_analysis
from datetime import datetime
import joblib
import pandas as pd
import os
import sys


# === Trust Lists ===
TRUSTED_DOMAINS = ['google.com', 'microsoft.com', 'paypal.com', 'amazon.com', 'apple.com', 'elitehubs.com']
PHISHY_DOMAINS = ['stopify.co', 'click-now-login.com', 'secure-login-alert.com']

# === Helper: Safe path for PyInstaller ===
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # PyInstaller temporary dir
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def analyze_email(email_text, subject=None, sender=None, return_output=False, full_details=False):
    lines = []

    # === 🧠 Feature Extraction ===
    features = extract_features(email_text)

    # === 🔍 Load Phishing ML Model (PyInstaller-safe path) ===
    model_path = resource_path(os.path.join("core", "phishing_model.pkl"))
    model = joblib.load(model_path)
    input_df = pd.DataFrame([features])
    prediction = model.predict(input_df)[0]
    label = "Phishing Email" if prediction == 1 else "Legitimate Email"

    # === 🔗 URL Risk Analysis ===
    url_risks = scan_urls(email_text) or []
    override_reasons = []

    # === 🧠 Psychological Manipulation ===
    tactics = detect_tactics(email_text) or []

    for u in url_risks:
        url = u.get('url', '')
        vt_verdict = u.get('vt_raw', {}).get('verdict', '').lower()
        domain = url.split("/")[2] if "://" in url else url

        # Trusted domains override
        if any(td in domain for td in TRUSTED_DOMAINS):
            continue

        # 🔴 Hardcoded phishy domains
        if any(pd in domain for pd in PHISHY_DOMAINS):
            label = "Phishing Email"
            override_reasons.append(f"🧨 Domain `{domain}` is known to be suspicious.")

        # VirusTotal verdict
        if vt_verdict == "malicious":
            label = "Phishing Email"
            override_reasons.append(f"☣️ VirusTotal marked `{domain}` as malicious.")
        elif vt_verdict == "suspicious":
            label = "Phishing Email"
            override_reasons.append(f"⚠️ VirusTotal marked `{domain}` as suspicious.")

        # ML model for URL
        if "malicious" in u.get('ml_result', '').lower():
            label = "Phishing Email"
            override_reasons.append(f"🤖 URL ML model flagged `{domain}` as malicious.")

        # Payload link
        if u.get('has_payload_link'):
            label = "Phishing Email"
            override_reasons.append(f"💥 Payload-style link found in `{domain}`.")

        # Anomaly Score
        if u.get('anomaly_score', 0) >= 2:
            label = "Phishing Email"
            override_reasons.append(f"🚨 Anomaly score {u['anomaly_score']} from `{domain}`.")

    # Keywords override only for unknown domains
    phishing_keywords = ['login', 'verify', 'reset', 'account', 'bank', 'password']
    if any(kw in email_text.lower() for kw in phishing_keywords):
        if any(all(td not in u.get('url', '') for td in TRUSTED_DOMAINS) for u in url_risks):
            label = "Phishing Email"
            override_reasons.append("🔐 Suspicious keywords used + untrusted domains.")

    if not override_reasons and prediction == 0:
        override_reasons.append("✅ No phishing indicators detected.")

    # === 📋 Report Assembly ===
    lines.append("\n🔍 REDHOOK RESULT:")
    lines.append(f"ML Prediction: {'Phishing' if prediction == 1 else 'Legitimate'}")
    lines.append("Overrides:")
    for reason in override_reasons:
        lines.append(f"• {reason}")

    lines.append("\n🔗 URL Risk Analysis:")
    if url_risks:
        for u in url_risks:
            lines.append(str(u))
    else:
        lines.append("No URLs found.")

    lines.append("\n🧠 Psychological Manipulation Detection:")
    if tactics:
        lines.append("Tactics detected: " + ", ".join(tactics))
    else:
        lines.append("None")

    explanation = generate_explanation(features, prediction, tactics, url_risks)
    lines.append("\n💬 Explanation (Generated Report):")
    lines.append(explanation)

    lines.append(f"\n🎯 FINAL VERDICT: {label}")
    final_output = "\n".join(lines)

    # === Save to DB ===
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    urls = [u.get('url', 'Unknown') for u in url_risks]
    if subject and sender:
        save_analysis(subject, sender, timestamp, label, tactics, urls, explanation)

    # === Return Output ===
    if full_details:
        return label, tactics, urls, explanation
    elif return_output:
        return final_output
    else:
        print(final_output)
        return None
