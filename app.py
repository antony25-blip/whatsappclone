import os
import logging
import pandas as pd
import numpy as np
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import re
from urllib.parse import urlparse
from math import log2
from collections import Counter
import validators
import onnxruntime as ort

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///messenger.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Load ONNX model
try:
    ort_session = ort.InferenceSession("models/model.onnx")
    logger.info("ONNX phishing model loaded successfully.")
except Exception as e:
    logger.error(f"Failed to load ONNX model: {e}")
    ort_session = None

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

with app.app_context():
    db.create_all()

# Feature extraction

def get_url_length(url):
    return len(str(url))

def has_https(url):
    try:
        parsed = urlparse(url)
        return 1 if parsed.scheme == 'https' else 0
    except:
        return 0

def count_subdomains(url):
    try:
        netloc = urlparse(url).netloc
        return netloc.count('.') - 1
    except:
        return 0

def has_suspicious_keywords(url):
    keywords = ['login', 'verify', 'account', 'update', 'secure', 'bank']
    return 1 if any(k in url.lower() for k in keywords) else 0

def has_ip_address(url):
    try:
        netloc = urlparse(url).netloc
        return 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', netloc) else 0
    except:
        return 0

def domain_entropy(url):
    try:
        domain = urlparse(url).netloc
        if not domain:
            return 0
        char_count = Counter(domain.lower())
        length = len(domain)
        entropy = -sum((c/length) * log2(c/length) for c in char_count.values())
        return entropy
    except:
        return 0

def count_special_chars(url):
    special_chars = set('@-_&%+=?#*()[]{}!|')
    return sum(url.count(c) for c in special_chars)

def path_depth(url):
    try:
        return urlparse(url).path.count('/')
    except:
        return 0

def has_suspicious_tld(url):
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win']
    try:
        domain = urlparse(url).netloc
        return 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
    except:
        return 0

def extract_features(url):
    return pd.DataFrame([{
        'url_length': get_url_length(url),
        'has_https': has_https(url),
        'subdomains': count_subdomains(url),
        'suspicious_keywords': has_suspicious_keywords(url),
        'has_ip': has_ip_address(url),
        'domain_entropy': domain_entropy(url),
        'special_chars': count_special_chars(url),
        'path_depth': path_depth(url),
        'suspicious_tld': has_suspicious_tld(url)
    }])

def extract_urls(text):
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|www\.[-\w./?=&%]+'
    return [url for url in re.findall(url_pattern, text) if validators.url(url)]

# Routes
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('messaging'))
        return "Invalid credentials."
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            return "Username already exists."
        db.session.add(User(username=username, password=password))
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/messaging')
def messaging():
    if 'username' not in session:
        return redirect(url_for('login'))
    current_user = session['username']
    users = User.query.filter(User.username != current_user).all()
    unread_counts = {u.username: Message.query.filter_by(sender=u.username, receiver=current_user, is_read=False).count() for u in users}
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

    for m in Message.query.filter_by(sender=receiver, receiver=current_user, is_read=False):
        m.is_read = True
    db.session.commit()

    message_data = []  # <-- ✅ Correctly indented here

    for m in messages:
        urls = extract_urls(m.message)
        is_phishing = False
        phishing_alert = None

        if urls:
            for url in urls:
                try:
                    if ort_session:
                        ort_inputs = {ort_session.get_inputs()[0].name: np.array([url])}
                        ort_outs = ort_session.run(None, ort_inputs)
                        pred = ort_outs[0][0]

                        if isinstance(pred, np.ndarray) and pred.shape[-1] == 2:
                            phishing_prob = float(pred[1])
                            prediction = "Phishing" if phishing_prob > 0.7 else "Legitimate"
                        else:
                            prediction = "Phishing" if pred == 1 else "Legitimate"

                        if prediction == "Phishing":
                            is_phishing = True
                            phishing_alert = f"⚠️ Warning: This link may be a phishing site → {url}"
                            break
                    else:
                        phishing_alert = f"Model not loaded. Cannot check: {url}"
                except Exception as e:
                    logger.error(f"Error checking URL {url}: {str(e)}")
                    phishing_alert = f"Error verifying URL safety: {str(e)}"

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
    new_msg = Message(
        sender=session['username'],
        receiver=request.form['receiver'],
        message=request.form['message']
    )
    db.session.add(new_msg)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/predict', methods=['POST'])
def predict():
    if ort_session is None:
        return jsonify({'error': 'Model not loaded'}), 500
    url = request.get_json().get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    try:
        features = extract_features(url)
        input_data = features.astype(np.float32).to_numpy()
        ort_inputs = {ort_session.get_inputs()[0].name: input_data}
        output = ort_session.run(None, ort_inputs)
        prob = output[0][0]
        prediction = "Phishing" if prob[1] > 0.7 else "Legitimate"
        return jsonify({
            'url': url,
            'prediction': prediction,
            'phishing_probability': float(prob[1])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/test_model')
def test_model():
    if ort_session is None:
        return jsonify({'error': 'ONNX model not loaded'}), 500

    test_urls = [
        "https://www.google.com",
        "https://paypal.login-verify.tk",
        "http://192.168.1.1/login",
        "http://apple.login-secure.com"
    ]

    results = []
    for url in test_urls:
        try:
            # INPUT MUST BE A LIST OF STRINGS
            ort_inputs = {ort_session.get_inputs()[0].name: np.array([url])}
            ort_outs = ort_session.run(None, ort_inputs)

            # Check output format — usually it's probabilities or class index
            prob_or_label = ort_outs[0][0]
            if isinstance(prob_or_label, np.ndarray) and prob_or_label.shape[-1] == 2:
                # [legit_prob, phishing_prob]
                phishing_prob = float(prob_or_label[1])
                prediction = "Phishing" if phishing_prob > 0.7 else "Legitimate"
            else:
                # assume label: 1 = phishing
                prediction = "Phishing" if prob_or_label == 1 else "Legitimate"
                phishing_prob = None

            results.append({
                'url': url,
                'prediction': prediction,
                'phishing_probability': phishing_prob
            })
        except Exception as e:
            results.append({
                'url': url,
                'error': str(e)
            })

    return jsonify(results)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
