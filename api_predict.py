# api_predict.py (place in D:\project s6)
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from urllib.parse import urlparse
import re
from math import log2
from collections import Counter

app = Flask(__name__)

# Feature extraction functions (same as predict.py)
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
        return 0

def count_subdomains(url):
    try:
        netloc = urlparse(str(url)).netloc or str(url).split('/')[0]
        return max(0, netloc.count('.') - 1)
    except ValueError:
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
        return 0

def count_special_chars(url):
    special_chars = set('@-_&%+=?#*()[]{}!|')
    return sum(str(url).count(char) for char in special_chars)

def path_depth(url):
    try:
        path = urlparse(str(url)).path
        return path.count('/') if path else 0
    except ValueError:
        return 0

def has_suspicious_tld(url):
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win']
    try:
        domain = urlparse(str(url)).netloc or str(url).split('/')[0]
        return 1 if any(domain.lower().endswith(tld) for tld in suspicious_tlds) else 0
    except ValueError:
        return 0

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

# Load model and scaler once at startup
try:
    model = joblib.load('phishing_model.pkl')
    scaler = joblib.load('scaler.pkl')
    print("Phishing model and scaler loaded successfully.")
except Exception as e:
    print(f"Error loading model/scaler: {str(e)}")
    model, scaler = None, None

@app.route('/predict', methods=['POST'])
def predict():
    if model is None or scaler is None:
        return jsonify({'error': 'Model or scaler not loaded'}), 500

    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    features = extract_features(url)
    features[['url_length', 'domain_entropy', 'special_chars', 'path_depth', 'subdomains']] = scaler.transform(
        features[['url_length', 'domain_entropy', 'special_chars', 'path_depth', 'subdomains']]
    )
    prob = model.predict_proba(features)[0]
    
    # Prediction logic (same as predict.py)
    if features['suspicious_tld'].iloc[0] == 1:
        prediction = "Phishing"
    elif features['has_https'].iloc[0] == 1 and features['has_ip'].iloc[0] == 0:
        prediction = "Legitimate"
    else:
        prediction = "Phishing" if prob[1] > 0.7 else "Legitimate"
    
    return jsonify({
        'url': url,
        'prediction': prediction,
        'phishing_probability': float(prob[1])
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)  # Port 5001 to avoid conflict with app.py