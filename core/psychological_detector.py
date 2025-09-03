# core/psychological_detector.py

def detect_tactics(email_text):
    tactics = []
    if "urgent" in email_text.lower():
        tactics.append("Urgency")
    if "click here" in email_text.lower():
        tactics.append("Call-to-action")
    if "verify your account" in email_text.lower():
        tactics.append("Account Verification")
    if "limited time" in email_text.lower():
        tactics.append("Scarcity")
    if "password" in email_text.lower():
        tactics.append("Credential Request")
    return tactics
