import re
import tldextract
import joblib
import os
import sys
import numpy as np
import base64
import requests
import time

# === CONFIG ===
API_KEY = "1be4d352935b6a0685cefb36186b7dd9132cf2bc5229dd3239f3778ec420bfc0"
VT_URL = "https://www.virustotal.com/api/v3/urls"

# === Helper: Safe path for PyInstaller ===
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # for PyInstaller
    except AttributeError:
        base_path = os.path.abspath(".")  # for normal execution
    return os.path.join(base_path, relative_path)

# === Load trained model ===
MODEL_PATH = resource_path(os.path.join("core", "url_model.pkl"))

model = joblib.load(MODEL_PATH)

# === Feature Extraction ===
def extract_features(url):
    ext = tldextract.extract(url)
    domain = ext.domain
    tld = ext.suffix
    full_domain = f"{domain}.{tld}"

    has_ip = bool(re.search(r'https?://\d+\.\d+\.\d+\.\d+', url))
    num_subdomains = len(ext.subdomain.split('.')) if ext.subdomain else 0
    suspicious_tld = int(tld in ['ru', 'cn', 'tk', 'zip'])
    uses_https = int(url.startswith("https://"))
    has_login_keyword = int(any(k in url.lower() for k in ['login', 'signin', 'account']))
    has_payload_query = int('.php?' in url or '.html?' in url or '?id=' in url)
    num_dashes = url.count('-')
    is_shortened = int(full_domain in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl'])
    url_length = len(url)

    return [url_length, int(has_ip), num_subdomains, suspicious_tld,
            uses_https, has_login_keyword, has_payload_query, num_dashes, is_shortened]

# === VirusTotal Verdict ===
def get_virustotal_verdict(url):
    try:
        headers = {"x-apikey": API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f"{VT_URL}/{url_id}"
        response = requests.get(report_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = sum(stats.values())
            verdict = "Malicious" if malicious > 0 else "Suspicious" if suspicious > 0 else "Clean"
            return {
                "verdict": verdict,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "total": total
            }
        else:
            return {"verdict": "Unknown", "error": f"Status: {response.status_code}"}
    except Exception as e:
        return {"verdict": "Unknown", "error": str(e)}

# === Main Scanner ===
def scan_urls(input_text):
    urls = re.findall(r'https?://\S+', input_text)
    if not urls and input_text.startswith("http"):
        urls = [input_text]

    results = []
    for url in urls:
        try:
            # ML Prediction
            features = extract_features(url)
            features_array = np.array(features).reshape(1, -1)
            ml_prediction = model.predict(features_array)[0]
            ml_verdict = "<font color='red'><b>⚠️ Malicious</b></font>" if ml_prediction == 1 else "<font color='green'><b>✅ Safe</b></font>"

            # VirusTotal Verdict
            vt = get_virustotal_verdict(url)
            vt_raw = vt.get("verdict", "Unknown")
            if vt_raw == "Malicious":
                vt_verdict = "<font color='red'><b>Malicious</b></font>"
            elif vt_raw == "Suspicious":
                vt_verdict = "<font color='orange'><b>Suspicious</b></font>"
            elif vt_raw == "Clean":
                vt_verdict = "<font color='green'><b>Clean</b></font>"
            else:
                vt_verdict = "<font color='gray'>Unknown</font>"

            # Return all details
            results.append({
                "url": url,
                "ml_result": ml_verdict,
                "vt_result": vt_verdict,
                "vt_stats": vt,
                "features": features
            })

        except Exception as e:
            results.append({
                "url": url,
                "ml_result": "❌ Error",
                "vt_result": "❌ Error",
                "features": [],
                "error": str(e)
            })

    return results
