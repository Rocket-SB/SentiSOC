"""
SentiSOC - Reservation Service
Manages resource reservations. Validates JWT from Auth Service.
"""
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt, datetime, os, logging, json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///reservations.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('sentisoc.reservation')

def security_log(event, user='anonymous', details=''):
    logger.info(json.dumps({"tag": "[SECURITY]", "event": event, "user": user,
                             "ip": request.remote_addr, "details": details}))

# ── Model ──────────────────────────────────────────────────────────────────────
class Reservation(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, nullable=False)
    username     = db.Column(db.String(80), nullable=False)
    resource_id  = db.Column(db.Integer, nullable=False)
    resource_name= db.Column(db.String(120))
    start_time   = db.Column(db.DateTime, nullable=False)
    end_time     = db.Column(db.DateTime, nullable=False)
    status       = db.Column(db.String(20), default='active')  # active | cancelled
    created      = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'user_id': self.user_id, 'username': self.username,
            'resource_id': self.resource_id, 'resource_name': self.resource_name,
            'start_time': self.start_time.isoformat(), 'end_time': self.end_time.isoformat(),
            'status': self.status, 'created': self.created.isoformat()
        }

# ── JWT Auth ───────────────────────────────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401
        try:
            payload = jwt.decode(auth.split(' ', 1)[1],
                                 app.config['SECRET_KEY'], algorithms=['HS256'])
            request.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(*args, **kwargs):
            if request.current_user.get('role') not in roles:
                security_log('ACCESS_DENIED', request.current_user.get('username'),
                             f'Required: {roles}')
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route('/api/reservations', methods=['GET'])
@token_required
def list_reservations():
    user = request.current_user
    # Admins see all; regular users see only their own
    if user['role'] == 'admin':
        items = Reservation.query.all()
    else:
        items = Reservation.query.filter_by(user_id=user['sub']).all()
    return jsonify({'reservations': [r.to_dict() for r in items]}), 200

@app.route('/api/reservations', methods=['POST'])
@role_required('admin', 'user')   # guests cannot reserve
def create_reservation():
    data = request.get_json() or {}
    required = ['resource_id', 'start_time', 'end_time']
    if not all(k in data for k in required):
        return jsonify({'error': f'Required: {required}'}), 400

    try:
        start = datetime.datetime.fromisoformat(data['start_time'])
        end   = datetime.datetime.fromisoformat(data['end_time'])
    except ValueError:
        return jsonify({'error': 'Invalid datetime format (ISO 8601)'}), 400

    if end <= start:
        return jsonify({'error': 'end_time must be after start_time'}), 400

    # Conflict check
    conflict = Reservation.query.filter(
        Reservation.resource_id == data['resource_id'],
        Reservation.status == 'active',
        Reservation.start_time < end,
        Reservation.end_time > start
    ).first()
    if conflict:
        return jsonify({'error': 'Resource already reserved for that time slot'}), 409

    user = request.current_user
    r = Reservation(
        user_id=user['sub'], username=user['username'],
        resource_id=data['resource_id'],
        resource_name=data.get('resource_name', f'Resource #{data["resource_id"]}'),
        start_time=start, end_time=end
    )
    db.session.add(r)
    db.session.commit()
    security_log('RESERVATION_CREATED', user['username'], f'resource={data["resource_id"]}')
    return jsonify({'message': 'Reservation created', 'reservation': r.to_dict()}), 201

@app.route('/api/reservations/<int:rid>', methods=['DELETE'])
@token_required
def cancel_reservation(rid):
    r = Reservation.query.get_or_404(rid)
    user = request.current_user
    # Users can only cancel their own; admins can cancel any
    if r.user_id != user['sub'] and user['role'] != 'admin':
        security_log('ACCESS_DENIED', user['username'], f'cancel reservation {rid}')
        return jsonify({'error': 'Cannot cancel another user\'s reservation'}), 403
    r.status = 'cancelled'
    db.session.commit()
    security_log('RESERVATION_CANCELLED', user['username'], f'reservation={rid}')
    return jsonify({'message': 'Reservation cancelled'}), 200

@app.route('/metrics')
def metrics():
    total     = Reservation.query.count()
    active    = Reservation.query.filter_by(status='active').count()
    cancelled = Reservation.query.filter_by(status='cancelled').count()
    lines = [
        '# HELP reservations_total Total reservations',
        '# TYPE reservations_total gauge',
        f'reservations_total{{status="active"}} {active}',
        f'reservations_total{{status="cancelled"}} {cancelled}',
        f'reservations_total{{status="all"}} {total}',
    ]
    return '\n'.join(lines), 200, {'Content-Type': 'text/plain'}

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'reservation-service'}), 200

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
