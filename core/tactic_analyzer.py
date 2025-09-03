def detect_tactics(email_text):
    email_lower = email_text.lower()
    detected = []

    # 🚨 Urgency
    urgency_keywords = ['act now', 'immediately', 'limited time', 'urgent', 'respond quickly']
    if any(kw in email_lower for kw in urgency_keywords):
        detected.append('Urgency')

    # 😱 Fear
    fear_keywords = ['account suspended', 'unauthorized', 'your access is blocked', 'security breach', 'violation detected']
    if any(kw in email_lower for kw in fear_keywords):
        detected.append('Fear')

    # 🧑‍💼 Authority
    authority_keywords = ['ceo', 'admin', 'it team', 'compliance', 'security officer']
    if any(kw in email_lower for kw in authority_keywords):
        detected.append('Authority')

    # 🤑 Greed
    greed_keywords = ['you’ve won', 'congratulations', 'claim prize', 'lottery', 'reward']
    if any(kw in email_lower for kw in greed_keywords):
        detected.append('Greed')

    return detected
