from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from database import query_db, insert_db
from functools import wraps
from datetime import timedelta
import os
import redis
from config import get_config
import logging

config = get_config()
r = redis.Redis.from_url(config.REDIS_URL) if config.REDIS_URL else None
logging.basicConfig(level=logging.INFO)

# JWT Setup (init in backend.py: jwt = JWTManager(app))
def init_jwt(app):
    app.config['JWT_SECRET_KEY'] = config.JWT_SECRET_KEY or os.getenv('JWT_SECRET_KEY', 'default_secret')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
    return JWTManager(app)

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
        return {
            'id': user_data['id'],
            'username': user_data['username'],
            'role': user_data['role']
        }
    return None

# Role-based decorators for JWT
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        claims = get_jwt()
        if claims.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def auditor_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        claims = get_jwt()
        if claims.get('role') not in ['admin', 'auditor']:
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
        # Use username as the identity instead of user ID
        access_token = create_access_token(
            identity=username,  # Use username as identity
            additional_claims={'username': username, 'role': user['role']}
        )
        # Cache session in Redis
        if r:
            try:
                r.setex(f'session_{username}', 3600, access_token)
            except:
                pass  # Ignore Redis errors in tests
        return jsonify({'success': True, 'access_token': access_token, 'role': user['role']})
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

def api_logout():
    try:
        user_id = get_jwt_identity()
        if r:
            r.delete(f'session_{user_id}')
    except:
        pass
    return jsonify({'success': True, 'message': 'Logged out successfully'})

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
        user = {'id': user_id, 'username': username, 'role': role}
        access_token = create_access_token(identity=user['id'], additional_claims={'username': user['username'], 'role': user['role']})
        return jsonify({'success': True, 'access_token': access_token, 'role': role})
    return jsonify({'success': False, 'error': 'Registration failed'}), 500

def api_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        try:
            # Get the JWT claims to ensure we have a valid token
            claims = get_jwt()
            if not claims:
                return jsonify({'error': 'Invalid token claims'}), 401
                
            # Add the user info to the request object for use in the endpoint
            request.user_id = get_jwt_identity()
            request.user_role = claims.get('role')
            
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': str(e)}), 401
    return decorated_function

def get_current_user_role():
    try:
        claims = get_jwt()
        return claims.get('role')
    except:
        return None

def validate_session():
    """
    Validate JWT token against Redis cache.
    """
    try:
        user_id = get_jwt_identity()
        if r:
            cached_token = r.get(f'session_{user_id}')
            if not cached_token:
                return False
        return True
    except:
        return False
