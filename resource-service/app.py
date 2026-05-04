"""
SentiSOC - Resource Service
Manages resources (servers, meeting rooms, etc.).
Only admins can create/delete; users can view available resources.
"""
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt, datetime, os, logging, json, time, random
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///resources.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('sentisoc.resource')

def security_log(event, user='anonymous', details=''):
    logger.info(json.dumps({"tag": "[SECURITY]", "event": event,
                             "user": user, "ip": request.remote_addr, "details": details}))

# ── Model ──────────────────────────────────────────────────────────────────────
class Resource(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(120), unique=True, nullable=False)
    type        = db.Column(db.String(50))   # server | room | device
    capacity    = db.Column(db.Integer, default=1)
    location    = db.Column(db.String(120))
    available   = db.Column(db.Boolean, default=True)
    cpu_usage   = db.Column(db.Float, default=0.0)   # simulated metric
    created_by  = db.Column(db.String(80))
    created     = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'type': self.type,
            'capacity': self.capacity, 'location': self.location,
            'available': self.available, 'cpu_usage': round(self.cpu_usage, 1),
            'created_by': self.created_by, 'created': self.created.isoformat()
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
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            return jsonify({'error': str(e)}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if request.current_user.get('role') != 'admin':
            security_log('ACCESS_DENIED', request.current_user.get('username'), 'Admin required')
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route('/api/resources', methods=['GET'])
@token_required
def list_resources():
    # Guests only see available resources
    user = request.current_user
    if user['role'] == 'guest':
        items = Resource.query.filter_by(available=True).all()
    else:
        items = Resource.query.all()
    return jsonify({'resources': [r.to_dict() for r in items]}), 200

@app.route('/api/resources/<int:rid>', methods=['GET'])
@token_required
def get_resource(rid):
    r = Resource.query.get_or_404(rid)
    if request.current_user['role'] == 'guest' and not r.available:
        security_log('ACCESS_DENIED', request.current_user['username'], f'resource {rid} unavailable')
        return jsonify({'error': 'Resource not available'}), 403
    return jsonify({'resource': r.to_dict()}), 200

@app.route('/api/resources', methods=['POST'])
@admin_required
def create_resource():
    data = request.get_json() or {}
    if not data.get('name'):
        return jsonify({'error': 'name is required'}), 400
    if Resource.query.filter_by(name=data['name']).first():
        return jsonify({'error': 'Resource name already exists'}), 409
    r = Resource(
        name=data['name'],
        type=data.get('type', 'server'),
        capacity=data.get('capacity', 1),
        location=data.get('location', 'Unknown'),
        created_by=request.current_user['username']
    )
    db.session.add(r)
    db.session.commit()
    security_log('RESOURCE_CREATED', request.current_user['username'], f'name={r.name}')
    return jsonify({'message': 'Resource created', 'resource': r.to_dict()}), 201

@app.route('/api/resources/<int:rid>', methods=['PATCH'])
@admin_required
def update_resource(rid):
    r = Resource.query.get_or_404(rid)
    data = request.get_json() or {}
    for field in ['name', 'type', 'capacity', 'location', 'available']:
        if field in data:
            setattr(r, field, data[field])
    db.session.commit()
    return jsonify({'message': 'Resource updated', 'resource': r.to_dict()}), 200

@app.route('/api/resources/<int:rid>', methods=['DELETE'])
@admin_required
def delete_resource(rid):
    r = Resource.query.get_or_404(rid)
    db.session.delete(r)
    db.session.commit()
    security_log('RESOURCE_DELETED', request.current_user['username'], f'id={rid}')
    return jsonify({'message': 'Resource deleted'}), 200

@app.route('/api/resources/simulate-load', methods=['POST'])
@admin_required
def simulate_load():
    """Simulate high CPU on a resource to trigger monitoring alerts."""
    data = request.get_json() or {}
    rid = data.get('resource_id')
    cpu = float(data.get('cpu', 85.0))
    r = Resource.query.get_or_404(rid)
    r.cpu_usage = cpu
    db.session.commit()
    security_log('LOAD_SIMULATED', request.current_user['username'],
                 f'resource={r.name} cpu={cpu}%')
    return jsonify({'message': f'CPU set to {cpu}% on {r.name}', 'resource': r.to_dict()}), 200

@app.route('/metrics')
def metrics():
    resources = Resource.query.all()
    total     = len(resources)
    available = sum(1 for r in resources if r.available)
    high_cpu  = [r for r in resources if r.cpu_usage > 80]

    lines = [
        '# HELP resource_count Total resources',
        '# TYPE resource_count gauge',
        f'resource_count{{status="total"}} {total}',
        f'resource_count{{status="available"}} {available}',
        '# HELP resource_cpu_usage CPU usage per resource',
        '# TYPE resource_cpu_usage gauge',
    ]
    for r in resources:
        lines.append(f'resource_cpu_usage{{name="{r.name}"}} {r.cpu_usage}')

    return '\n'.join(lines), 200, {'Content-Type': 'text/plain'}

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'resource-service'}), 200

with app.app_context():
    db.create_all()
    # Seed demo resources
    if Resource.query.count() == 0:
        demo = [
            Resource(name='Web Server 01', type='server', capacity=1,
                     location='DC-A Rack-3', cpu_usage=12.5, created_by='admin'),
            Resource(name='DB Server 01',  type='server', capacity=1,
                     location='DC-A Rack-4', cpu_usage=34.2, created_by='admin'),
            Resource(name='Meeting Room A', type='room',  capacity=10,
                     location='Floor 2', available=True, created_by='admin'),
            Resource(name='GPU Node 01',   type='device', capacity=1,
                     location='DC-B Rack-1', cpu_usage=67.0, created_by='admin'),
        ]
        for d in demo:
            db.session.add(d)
        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
