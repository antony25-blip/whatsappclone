import joblib
import pandas as pd
from urllib.parse import urlparse
import re
from math import log2
from collections import Counter

# Feature extraction functions (unchanged)
def get_url_length(url):
    return len(str(url))

def has_https(url):
    try:
        url_str = str(url)
        parsed = urlparse(url_str)
        if parsed.scheme:
            return 1 if parsed.scheme == 'https' else 0
        legit_tlds = ['.com', '.org', '.edu', '.gov', '.net']
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win']
        keywords = ['login', 'verify', 'account', 'update', 'secure', 'bank']
        domain = url_str.split('/')[0].lower()
        if any(domain.endswith(tld) for tld in legit_tlds) and not any(kw in url_str.lower() for kw in keywords):
            return 1
        if any(domain.endswith(tld) for tld in suspicious_tlds) or any(kw in url_str.lower() for kw in keywords):
            return 0
        return 0
    except ValueError:
        print(f"Invalid URL in has_https: {url}")
        return 0

def count_subdomains(url):
    try:
        netloc = urlparse(str(url)).netloc or str(url).split('/')[0]
        return max(0, netloc.count('.') - 1)
    except ValueError:
        print(f"Invalid URL in count_subdomains: {url}")
        return 0

def has_suspicious_keywords(url):
    keywords = ['login', 'verify', 'account', 'update', 'secure', 'bank']
    return 1 if any(keyword in str(url).lower() for keyword in keywords) else 0

def has_ip_address(url):
    try:
        netloc = urlparse(str(url)).netloc or str(url).split('/')[0]
        ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
        return 1 if re.match(ip_pattern, netloc) else 0
    except ValueError:
        print(f"Invalid URL in has_ip_address: {url}")
        return 0

def domain_entropy(url):
    try:
        domain = urlparse(str(url)).netloc or str(url).split('/')[0]
        if not domain:
            return 0
        length = len(domain)
        char_count = Counter(domain.lower())
        entropy = -sum((count / length) * log2(count / length) for count in char_count.values())
        return entropy
    except ValueError:
        print(f"Invalid URL in domain_entropy: {url}")
        return 0

def count_special_chars(url):
    special_chars = set('@-_&%+=?#*()[]{}!|')
    return sum(str(url).count(char) for char in special_chars)

def path_depth(url):
    try:
        path = urlparse(str(url)).path
        return path.count('/') if path else 0
    except ValueError:
        print(f"Invalid URL in path_depth: {url}")
        return 0

def has_suspicious_tld(url):
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win']
    try:
        domain = urlparse(str(url)).netloc or str(url).split('/')[0]
        return 1 if any(domain.lower().endswith(tld) for tld in suspicious_tlds) else 0
    except ValueError:
        print(f"Invalid URL in has_suspicious_tld: {url}")
        return 0

# Extract features as DataFrame
def extract_features(url):
    features = {
        'url_length': get_url_length(url),
        'has_https': has_https(url),
        'subdomains': count_subdomains(url),
        'suspicious_keywords': has_suspicious_keywords(url),
        'has_ip': has_ip_address(url),
        'domain_entropy': domain_entropy(url),
        'special_chars': count_special_chars(url),
        'path_depth': path_depth(url),
        'suspicious_tld': has_suspicious_tld(url)
    }
    return pd.DataFrame([features])

# Predict with probabilities and threshold
def predict_url(url):
    model = joblib.load('phishing_model.pkl')
    scaler = joblib.load('scaler.pkl')
    features = extract_features(url)
    print(f"Raw features for {url}: {features.to_dict(orient='records')[0]}")
    features[['url_length', 'domain_entropy', 'special_chars', 'path_depth', 'subdomains']] = scaler.transform(features[['url_length', 'domain_entropy', 'special_chars', 'path_depth', 'subdomains']]
    )
    print(f"Scaled features for {url}: {features.to_dict(orient='records')[0]}")
    prob = model.predict_proba(features)[0]
    print(f"Probabilities for {url}: Legitimate={prob[0]:.2f}, Phishing={prob[1]:.2f}")
    
    # Rule 1: Suspicious TLD → Phishing
    if features['suspicious_tld'].iloc[0] == 1:
        return "Phishing"
    
    # Rule 2: HTTPS and no IP → Legitimate (allow keywords like "secure")
    if features['has_https'].iloc[0] == 1 and features['has_ip'].iloc[0] == 0:
        return "Legitimate"
    
    # Rule 3: Threshold 0.7 for remaining cases
    prediction = 1 if prob[1] > 0.7 else 0
    return "Phishing" if prediction == 1 else "Legitimate"

# Test URLs
test_urls = [
    "https://www.google.com",
    "http://192.168.1.1/login",
    "https://secure-bank-xyz.tk/folder/subfolder",
    "http://x7k9p2m.cf?verify=1",
    "http://micr0soft-login.xyz",
    "https://amazon.login-confirmation.com",
    "https://nbrs.xyz/kfc-buckets",
    "https://paypal.com/secure",
    "http://apple.login-secure.com"
    
]

print("Testing URLs:")
for url in test_urls:
    result = predict_url(url)
    print(f"{url}: {result}\n")