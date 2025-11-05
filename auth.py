from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import redirect, url_for, flash, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from database import query_db, insert_db
import os

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'portal_login'
login_manager.login_message = 'Please log in to access this page.'

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user_data = query_db('SELECT id, username, role FROM users WHERE id = ?', (user_id,), one=True)
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['role'])
    return None

def init_auth(app):
    login_manager.init_app(app)

def hash_password(password):
    return generate_password_hash(password)

def verify_password(password, hash):
    return check_password_hash(hash, password)

def create_user(username, password, role='auditor'):
    password_hash = hash_password(password)
    user_id = insert_db('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                        (username, password_hash, role))
    return user_id

def authenticate_user(username, password):
    user_data = query_db('SELECT id, username, password_hash, role FROM users WHERE username = ?', (username,), one=True)
    if user_data and verify_password(password, user_data['password_hash']):
        user = User(user_data['id'], user_data['username'], user_data['role'])
        return user
    return None

# Role-based decorator
def admin_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def auditor_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'auditor']:
            return jsonify({'error': 'Auditor or admin access required'}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# API endpoints helpers (for JSON responses)
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = authenticate_user(username, password)
    if user:
        login_user(user)
        return jsonify({'success': True, 'token': f'user_{user.id}_{user.username}', 'role': user.role})
    return jsonify({'success': False}), 401

def api_logout():
    logout_user()
    return jsonify({'success': True})

def api_register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'auditor')
    # Check if user exists
    existing = query_db('SELECT id FROM users WHERE username = ?', (username,), one=True)
    if existing:
        return jsonify({'success': False, 'error': 'User already exists'}), 400
    user_id = create_user(username, password, role)
    if user_id:
        user = User(user_id, username, role)
        login_user(user)
        return jsonify({'success': True, 'role': role})
    return jsonify({'success': False, 'error': 'Registration failed'}), 500

def verify_api_token(token):
    # Token format: user_{user_id}_{username}
    parts = token.split('_')
    if len(parts) == 3 and parts[0] == 'user':
        try:
            user_id = int(parts[1])
            username = parts[2]
            user_data = query_db('SELECT id, username, role FROM users WHERE id = ?', (user_id,), one=True)
            if user_data and user_data['username'] == username:
                return User(user_data['id'], user_data['username'], user_data['role'])
        except ValueError:
            pass
    return None

def api_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401
        token = auth_header.split(' ')[1]
        user = verify_api_token(token)
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        # Set current_user for compatibility
        from flask_login import current_user
        current_user._get_current_object = lambda: user
        return f(*args, **kwargs)
    return decorated_function

def get_current_user_role():
    if current_user.is_authenticated:
        return current_user.role
    return None
