from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Encryption key generation
def generate_key():
    return Fernet.generate_key()

# Encrypt and decrypt functions
def encrypt_file(file_path):
    key = generate_key()
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = fernet.encrypt(file.read())
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)
    return key

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        decrypted_data = fernet.decrypt(file.read())
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'], method='sha256')
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)
            encrypt_file(file_path)
            return redirect(url_for('home'))
    return render_template('upload.html')

@app.route('/download/<filename>', methods=['GET'])
@login_required
def download(filename):
    file_path = os.path.join('uploads', filename)
    decrypt_file(file_path, key)  # Provide the correct key for decryption
    return send_file(file_path, as_attachment=True)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
