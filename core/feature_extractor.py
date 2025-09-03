import re
import tldextract

SUSPICIOUS_WORDS = ['urgent', 'verify', 'update', 'suspend', 'click here', 'act now']

def extract_features(email_text):
    features = {}
    email_lower = email_text.lower()

    features['suspicious_words'] = sum(word in email_lower for word in SUSPICIOUS_WORDS)
    urls = re.findall(r'https?://\S+', email_text)
    features['num_urls'] = len(urls)

    features['fake_domain'] = 0
    for url in urls:
        domain = tldextract.extract(url).domain
        if domain not in ['google', 'microsoft', 'apple', 'paypal']:
            features['fake_domain'] += 1

    features['has_urgency'] = int(any(word in email_lower for word in ['act now', 'immediately', 'limited time']))

    return features
