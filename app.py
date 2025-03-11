from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)
    receiver = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

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
    
    # Fetch unread messages count for each user
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
    
    return jsonify([{'sender': m.sender, 'message': m.message, 'timestamp': m.timestamp.strftime('%Y-%m-%d %H:%M:%S')} for m in messages])

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

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

