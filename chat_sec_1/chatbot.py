from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import logging
from datetime import datetime, timedelta
import joblib
from werkzeug.security import generate_password_hash, check_password_hash
import os
from collections import defaultdict
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///db.sqlite')

# Настройка базы данных
db = SQLAlchemy(app)

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Настройка логирования
logging.basicConfig(filename='hack_attempts.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

# Загрузка обученной модели и векторизатора
model = joblib.load('hack_detection_model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

# Определение модели пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


# Загрузка пользователя
@login_manager.user_loader
def load_user(user_id):
    app.logger.info(f'Loading user with ID: {user_id}')
    return User.query.get(int(user_id))

# Функция для определения типа кибератаки с использованием модели
def detect_attack(message):
    X = vectorizer.transform([message])
    attack_type = model.predict(X)[0]
    return attack_type

# Логирование атак
def log_attack(message, attack_type):
    with open('hack_attempts.log', 'a') as log_file:
        log_file.write(f'{datetime.now()} - {message} - {attack_type}\n')

# Отслеживание запросов для предотвращения DDoS атак
request_counts = defaultdict(list)
REQUEST_LIMIT = 100  # Порог запросов
TIME_WINDOW = 60  # Временное окно в секундах

def is_ddos_attempt(ip):
    current_time = time.time()
    request_counts[ip] = [timestamp for timestamp in request_counts[ip] if current_time - timestamp < TIME_WINDOW]
    request_counts[ip].append(current_time)
    return len(request_counts[ip]) > REQUEST_LIMIT

@app.route('/')
def index():
    if current_user.is_authenticated:
        app.logger.info('User is authenticated, redirecting to chat')
        return redirect(url_for('chat'))
    app.logger.info('User is not authenticated, showing index')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        app.logger.info(f'Login attempt for username: {username}')
        user = User.query.filter_by(username=username).first()
        if user:
            app.logger.info(f'User found: {user.username}')
        else:
            app.logger.info('User not found')
        if user and check_password_hash(user.password, password):
            login_user(user)
            app.logger.info(f'User {username} logged in successfully')
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password')
            app.logger.info(f'Failed login attempt for username {username}')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Проверка, существует ли уже пользователь с таким именем пользователя
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is not None:
            flash('Username already exists')
            app.logger.info(f'Username {username} already exists')
            return redirect(url_for('signup'))

        hash_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hash_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        app.logger.info(f'New user {username} signed up and logged in successfully')
        return redirect(url_for('chat'))
    return render_template('signup.html')

@app.route('/chat')
@login_required
def chat():
    app.logger.info('User accessed the chat page')
    return render_template('chat.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Проверка, существует ли уже пользователь с таким именем пользователя
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != current_user.id:
            flash('Username already exists')
            return redirect(url_for('profile'))

        current_user.username = username
        if password:
            current_user.password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Profile updated successfully')
        app.logger.info(f'User {current_user.username} updated their profile')
        return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    app.logger.info('User logged out')
    return redirect(url_for('login'))

@app.route('/chatbot', methods=['POST'])
@login_required
def chatbot():
    user_message = request.json.get('message')
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400

    # Получение IP-адреса пользователя
    user_ip = request.remote_addr

    # Логирование DDoS-атак
    if is_ddos_attempt(user_ip):
        logging.info(f'DDoS attempt detected from IP {user_ip}')
        return jsonify({'error': 'Too many requests'}), 429

    # Определение типа атаки
    attack_type = detect_attack(user_message)
    if attack_type != 'legitimate':
        log_attack(user_message, attack_type)
        logging.info(f'Hacking attempt detected from IP {user_ip}: {user_message} - {attack_type}')
        return jsonify({'response': f'Alert: {attack_type} attack detected!'}), 200

    # Ответ чат-бота (можно заменить на более сложный AI ответ)
    bot_response = 'Ваше сообщение получено.'

    return jsonify({'response': bot_response})

# Обработчики ошибок
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)