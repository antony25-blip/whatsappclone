from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import re
import validators
import joblib
import pandas as pd
from urllib.parse import urlparse
from math import log2
from collections import Counter
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')  # Use environment variable for production
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://myuser:mypassword@localhost:5432/minipro_phising')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are secure in production (HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Load model and scaler
try:
    model = joblib.load('phishing_model.pkl')
    scaler = joblib.load('scaler.pkl')
    print("Phishing model and scaler loaded successfully.")
except Exception as e:
    print(f"Error loading model/scaler: {str(e)}")
    model, scaler = None, None

# Feature extraction functions
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

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)
    receiver = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

# Create database tables
with app.app_context():
    db.create_all()

# Function to extract URLs from text
def extract_urls(text):
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|www\.[-\w./?=&%]+'
    urls = re.findall(url_pattern, text)
    valid_urls = [url for url in urls if validators.url(url)]
    return valid_urls

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('messaging'))
        
        return "Invalid credentials. Please try again."
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        if User.query.filter_by(username=username).first():
            return "Username already exists. Please choose another one."
        
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/messaging')
def messaging():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_user = session['username']
    users = User.query.filter(User.username != current_user).all()
    
    unread_counts = {user.username: Message.query.filter_by(sender=user.username, receiver=current_user, is_read=False).count() for user in users}
    
    return render_template('messaging.html', users=users, unread_counts=unread_counts)

@app.route('/get_messages/<receiver>', methods=['GET'])
def get_messages(receiver):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_user = session['username']
    messages = Message.query.filter(
        ((Message.sender == current_user) & (Message.receiver == receiver)) |
        ((Message.sender == receiver) & (Message.receiver == current_user))
    ).order_by(Message.timestamp).all()
    
    # Mark messages as read
    unread_messages = Message.query.filter_by(sender=receiver, receiver=current_user, is_read=False).all()
    for message in unread_messages:
        message.is_read = True
    db.session.commit()
    
    # Process messages for URLs and phishing detection
    message_data = []
    for m in messages:
        urls = extract_urls(m.message)
        is_phishing = False
        phishing_alert = None
        
        if urls:
            for url in urls:
                try:
                    # Directly call the prediction logic
                    if model is None or scaler is None:
                        raise Exception("Model or scaler not loaded")
                    
                    features = extract_features(url)
                    features[['url_length', 'domain_entropy', 'special_chars', 'path_depth', 'subdomains']] = scaler.transform(
                        features[['url_length', 'domain_entropy', 'special_chars', 'path_depth', 'subdomains']]
                    )
                    prob = model.predict_proba(features)[0]
                    
                    if features['suspicious_tld'].iloc[0] == 1:
                        prediction = "Phishing"
                    elif features['has_https'].iloc[0] == 1 and features['has_ip'].iloc[0] == 0:
                        prediction = "Legitimate"
                    else:
                        prediction = "Phishing" if prob[1] > 0.7 else "Legitimate"
                    
                    if prediction == 'Phishing':
                        is_phishing = True
                        phishing_alert = f"Warning: The URL '{url}' may be a phishing link!"
                        break
                except Exception as e:
                    print(f"Error checking URL {url}: {str(e)}")
                    phishing_alert = f"Error checking URL '{url}': Unable to verify safety."
        
        message_data.append({
            'sender': m.sender,
            'message': m.message,
            'timestamp': m.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_phishing': is_phishing,
            'phishing_alert': phishing_alert
        })
    
    return jsonify(message_data)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    sender = session['username']
    receiver = request.form['receiver']
    message_content = request.form['message']
    
    new_message = Message(sender=sender, receiver=receiver, message=message_content)
    db.session.add(new_message)
    db.session.commit()
    
    return jsonify({"success": True})

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

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
    
    # Prediction logic
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

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)