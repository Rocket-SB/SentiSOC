"""
SentiSOC - Auth Service
Handles user registration, login, JWT token issuance, and RBAC.
"""

from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import datetime
import os
import logging
import json
from functools import wraps

# ── App Setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///auth.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Rate limiter — blocks brute-force attempts
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ── Security Logger ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger('sentisoc.auth')

def security_log(event: str, user: str = 'anonymous', details: str = ''):
    """Emit a structured [SECURITY] log line for Loki/ELK ingestion."""
    logger.info(json.dumps({
        "tag": "[SECURITY]",
        "event": event,
        "user": user,
        "ip": request.remote_addr,
        "details": details
    }))

# ── Models ─────────────────────────────────────────────────────────────────────
VALID_ROLES = {'admin', 'user', 'guest'}

class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80),  unique=True, nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role     = db.Column(db.String(20),  default='user')   # admin | user | guest
    active   = db.Column(db.Boolean,     default=True)
    created  = db.Column(db.DateTime,    default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'active': self.active
        }

class LoginAttempt(db.Model):
    """Stores every login attempt for anomaly detection."""
    id        = db.Column(db.Integer, primary_key=True)
    username  = db.Column(db.String(80))
    ip        = db.Column(db.String(45))
    success   = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ── JWT Helpers ────────────────────────────────────────────────────────────────
JWT_EXPIRY_HOURS = 8

def generate_token(user: User) -> str:
    payload = {
        'sub':      user.id,
        'username': user.username,
        'role':     user.role,
        'iat':      datetime.datetime.utcnow(),
        'exp':      datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token: str) -> dict:
    return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

def token_required(f):
    """Decorator: validates Bearer JWT on every protected route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        token = auth_header.split(' ', 1)[1]
        try:
            payload = decode_token(token)
            request.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    """Decorator: restricts endpoint to specific roles."""
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(*args, **kwargs):
            if request.current_user.get('role') not in roles:
                security_log('ACCESS_DENIED', request.current_user.get('username'),
                             f'Required roles: {roles}')
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── Routes: Auth ───────────────────────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    required = ['username', 'email', 'password']
    if not all(k in data for k in required):
        return jsonify({'error': f'Required fields: {required}'}), 400

    role = data.get('role', 'user')
    if role not in VALID_ROLES:
        return jsonify({'error': f'Role must be one of {list(VALID_ROLES)}'}), 400

    # Only admins can create admin accounts via API key header
    if role == 'admin' and request.headers.get('X-Admin-Key') != os.environ.get('ADMIN_KEY', 'admin-secret'):
        return jsonify({'error': 'Admin key required to create admin account'}), 403

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already taken'}), 409
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409

    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], email=data['email'],
                password=hashed, role=role)
    db.session.add(user)
    db.session.commit()

    security_log('USER_REGISTERED', data['username'], f'role={role}')
    token = generate_token(user)
    return jsonify({'message': 'Registered successfully', 'token': token,
                    'user': user.to_dict()}), 201


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")   # brute-force protection
def login():
    data = request.get_json() or {}
    user = User.query.filter_by(username=data.get('username')).first()
    success = False

    if user and bcrypt.check_password_hash(user.password, data.get('password', '')):
        if not user.active:
            return jsonify({'error': 'Account disabled'}), 403
        success = True
        token = generate_token(user)
        security_log('LOGIN_SUCCESS', user.username)
        response = {'token': token, 'user': user.to_dict()}
        status = 200
    else:
        security_log('LOGIN_FAILURE', data.get('username', 'unknown'))
        response = {'error': 'Invalid credentials'}
        status = 401

    # Record every attempt for anomaly detection
    attempt = LoginAttempt(
        username=data.get('username', ''),
        ip=request.remote_addr,
        success=success
    )
    db.session.add(attempt)
    db.session.commit()

    return jsonify(response), status


@app.route('/api/auth/validate', methods=['GET'])
@token_required
def validate_token():
    return jsonify({'valid': True, 'user': request.current_user}), 200


@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    # Stateless JWT: client discards token; here we just log it
    security_log('LOGOUT', request.current_user.get('username'))
    return jsonify({'message': 'Logged out'}), 200

# ── Routes: Admin ──────────────────────────────────────────────────────────────
@app.route('/api/admin/users', methods=['GET'])
@role_required('admin')
def list_users():
    users = User.query.all()
    return jsonify({'users': [u.to_dict() for u in users]}), 200


@app.route('/api/admin/users/<int:uid>/role', methods=['PATCH'])
@role_required('admin')
def change_role(uid):
    data = request.get_json() or {}
    new_role = data.get('role')
    if new_role not in VALID_ROLES:
        return jsonify({'error': 'Invalid role'}), 400
    user = User.query.get_or_404(uid)
    user.role = new_role
    db.session.commit()
    security_log('ROLE_CHANGED', request.current_user['username'],
                 f'target={user.username} new_role={new_role}')
    return jsonify({'message': f'Role updated to {new_role}', 'user': user.to_dict()})


@app.route('/api/admin/login-attempts', methods=['GET'])
@role_required('admin')
def login_attempts():
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(100).all()
    return jsonify({'attempts': [
        {'username': a.username, 'ip': a.ip,
         'success': a.success, 'timestamp': a.timestamp.isoformat()}
        for a in attempts
    ]})

# ── Routes: Metrics (Prometheus format) ───────────────────────────────────────
@app.route('/metrics', methods=['GET'])
@limiter.exempt
def metrics():
    """Simple Prometheus-compatible metrics endpoint."""
    total   = LoginAttempt.query.count()
    failed  = LoginAttempt.query.filter_by(success=False).count()
    success = LoginAttempt.query.filter_by(success=True).count()
    users   = User.query.count()

    lines = [
        '# HELP auth_login_attempts_total Total login attempts',
        '# TYPE auth_login_attempts_total counter',
        f'auth_login_attempts_total{{result="success"}} {success}',
        f'auth_login_attempts_total{{result="failure"}} {failed}',
        '# HELP auth_registered_users_total Registered users',
        '# TYPE auth_registered_users_total gauge',
        f'auth_registered_users_total {users}',
    ]
    return '\n'.join(lines), 200, {'Content-Type': 'text/plain'}

# ── Health Check ───────────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'auth-service'}), 200

# ── Bootstrap ─────────────────────────────────────────────────────────────────
def seed_demo_users():
    """Create demo users for each role if they don't exist."""
    demo = [
        ('admin',     'admin@sentisoc.local',     'Admin@123',  'admin'),
        ('john_user', 'john@sentisoc.local',       'User@123',   'user'),
        ('guest1',    'guest1@sentisoc.local',     'Guest@123',  'guest'),
    ]
    for username, email, password, role in demo:
        if not User.query.filter_by(username=username).first():
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.add(User(username=username, email=email,
                                password=hashed, role=role))
    db.session.commit()
    logger.info('[BOOT] Demo users seeded')

with app.app_context():
    db.create_all()
    seed_demo_users()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
