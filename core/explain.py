
def generate_explanation(features, prediction, tactics, url_risks):
    explanation_lines = []

    # 🎯 ML Verdict Explanation
    if prediction == 1:
        explanation_lines.append("🤖 **ML Model Verdict**: The email was classified as a *Phishing Email* based on its structure, keywords, and statistical patterns.")
    else:
        explanation_lines.append("✅ **ML Model Verdict**: The email appears *Legitimate* based on feature analysis.")

    # 🔗 URL Risk Analysis
    if url_risks:
        flagged = False
        for i, url in enumerate(url_risks, 1):
            explanation_lines.append(f"\n🔗 **URL {i}:** `{url.get('url', 'Unknown')}`")
            if url.get('is_malicious_vt'):
                explanation_lines.append("• 🚨 Flagged by VirusTotal as malicious.")
                flagged = True
            if url.get('has_payload_link'):
                explanation_lines.append("• ⚠️ Detected as payload-style link (`.php?id=` or `.html?`).")
                flagged = True
            if url.get('model_flagged'):
                explanation_lines.append("• 🧠 ML model marked this URL as suspicious.")
                flagged = True
            if url.get('anomaly_score', 0) >= 1:
                explanation_lines.append(f"• 🔍 Anomaly score: `{url.get('anomaly_score')}`")
                flagged = True
        if not flagged:
            explanation_lines.append("• ✅ No malicious indicators found in URLs.")
    else:
        explanation_lines.append("\n🔗 **URL Analysis**: No URLs found in the email.")

    # 🧠 Psychological Tactics
    if tactics:
        explanation_lines.append("\n🧠 **Phishing Tactics Detected**:")
        for tactic in tactics:
            explanation_lines.append(f"• `{tactic}` – commonly used to manipulate victims emotionally or psychologically.")
    else:
        explanation_lines.append("\n🧠 **Phishing Tactics**: None detected.")

    return "\n".join(explanation_lines)
