from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import requests, os, base64, json
from datetime import datetime  # NOUVEAU: Pour horodater les alertes

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'frontend-secret')

AUTH_URL        = os.environ.get('AUTH_URL',        'http://auth-service:5001')
RESERVATION_URL = os.environ.get('RESERVATION_URL', 'http://reservation-service:5002')
RESOURCE_URL    = os.environ.get('RESOURCE_URL',    'http://resource-service:5003')
ALERTMANAGER_URL= os.environ.get('ALERTMANAGER_URL','http://alertmanager:9093')
PROMETHEUS_URL  = os.environ.get('PROMETHEUS_URL',  'http://prometheus:9090')

# Keycloak Configuration
KEYCLOAK_REALM = 'sentisoc'
CLIENT_ID = 'sentisoc-frontend'
KEYCLOAK_TOKEN_URL = f"http://keycloak:8080/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
KEYCLOAK_AUTH_URL = f"http://localhost:8081/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"

LOKI_URL = os.environ.get('LOKI_URL', 'http://loki:3100')

# Fichier où l'on va stocker l'historique des alertes

HISTORY_FILE = '/tmp/alert_history.json'

def auth_headers():
    token = session.get('token', '')
    return {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

def api_get(url):
    try:
        r = requests.get(url, headers=auth_headers(), timeout=5)
        return r.json(), r.status_code
    except Exception as e:
        return {'error': str(e)}, 503

def api_post(url, data):
    try:
        r = requests.post(url, json=data, headers=auth_headers(), timeout=5)
        return r.json(), r.status_code
    except Exception as e:
        return {'error': str(e)}, 503
    
def get_prom_metric(query):
    """Helper to fetch real hardware metrics from Prometheus"""
    try:
        res = requests.get(f"{PROMETHEUS_URL}/api/v1/query", params={'query': query}, timeout=3)
        if res.status_code == 200:
            data = res.json()
            if data['data']['result']:
                # Extract the metric, convert to float, and round to 1 decimal place
                return round(float(data['data']['result'][0]['value'][1]), 1)
    except Exception as e:
        print(f"Prometheus query failed: {e}")
    return 0.0 # Return 0 if Prometheus is unreachable

@app.route('/')
def index():
    if 'token' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        data = {'username': request.form['username'],
                'password': request.form['password']}
        result, status = api_post(f'{AUTH_URL}/api/auth/login', data)
        if status == 200:
            session['token'] = result['token']
            session['user']  = result['user']
            return redirect(url_for('dashboard'))
        error = result.get('error', 'Login failed')
    return render_template('login.html', error=error)

@app.route('/login/sso')
def login_sso():
    """Step 1: Redirect user to Keycloak for authentication"""
    redirect_uri = url_for('sso_callback', _external=True)
    auth_url = f"{KEYCLOAK_AUTH_URL}?client_id={CLIENT_ID}&response_type=code&redirect_uri={redirect_uri}&scope=openid profile email"
    return redirect(auth_url)

@app.route('/callback')
def sso_callback():
    """Step 2: Catch the authorization code and exchange it for a token"""
    code = request.args.get('code')
    if not code:
        return redirect(url_for('login'))

    redirect_uri = url_for('sso_callback', _external=True)
    
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'redirect_uri': redirect_uri
    }
    
    try:
        # Step A: Get the Token
        token_res = requests.post(KEYCLOAK_TOKEN_URL, data=token_data, timeout=15)
        if token_res.status_code != 200:
            return render_template('login.html', error=f"SSO Token Denied (HTTP {token_res.status_code}): {token_res.text}")
            
        token_json = token_res.json()
        access_token = token_json.get('access_token')
        id_token = token_json.get('id_token') # Grab the ID token!
        
        if not access_token or not id_token:
            return render_template('login.html', error="Keycloak approved the login but did not send the tokens.")
        
        # Step B: BYPASS THE NETWORK! Decode the ID Token locally.
        payload_part = id_token.split('.')[1]
        payload_part += '=' * (-len(payload_part) % 4)
        user_info = json.loads(base64.urlsafe_b64decode(payload_part).decode('utf-8'))
        
        # Step C: Bridge the session
        session['token'] = access_token
        session['user'] = {
            'username': user_info.get('preferred_username', 'sso_user'),
            'role': 'user', 
            'email': user_info.get('email', '')
        }
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        return render_template('login.html', error=f"Network Crash: {str(e)}")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'token' not in session:
        return redirect(url_for('login'))
    user = session.get('user', {})
    
    # 1. Fetch Logical Inventory (Database)
    resources,    _ = api_get(f'{RESOURCE_URL}/api/resources')
    reservations, _ = api_get(f'{RESERVATION_URL}/api/reservations')
    
    # 2. Fetch Real Physical Infrastructure (Prometheus)
    cpu_query = '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100)'
    ram_query = '100 * (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))'
    disk_query = '100 - ((node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100)'
    
    host_metrics = {
        'cpu': get_prom_metric(cpu_query),
        'ram': get_prom_metric(ram_query),
        'disk': get_prom_metric(disk_query)
    }

    return render_template('dashboard.html',
                           user=user,
                           resources=resources.get('resources', []),
                           reservations=reservations.get('reservations', []),
                           server=host_metrics)

@app.route('/admin')
def admin():
    if session.get('user', {}).get('role') != 'admin':
        return redirect(url_for('dashboard'))
    users, _ = api_get(f'{AUTH_URL}/api/admin/users')
    attempts, _ = api_get(f'{AUTH_URL}/api/admin/login-attempts')
    return render_template('admin.html',
                           user=session['user'],
                           users=users.get('users', []),
                           attempts=attempts.get('attempts', []))

# --- NOUVEAU : RÉCEPTEUR WEBHOOK POUR L'HISTORIQUE ---
@app.route('/api/webhook/alerts', methods=['POST'])
def receive_alert_webhook():
    data = request.json
    
    # Charger l'historique existant
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        except json.JSONDecodeError:
            history = []

    # Ajouter les nouvelles alertes à l'historique
    if data and 'alerts' in data:
        for alert in data['alerts']:
            new_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": alert.get('status', 'unknown'),
                "name": alert.get('labels', {}).get('alertname', 'Inconnu'),
                "severity": alert.get('labels', {}).get('severity', 'info'),
                "description": alert.get('annotations', {}).get('description', '')
            }
            history.insert(0, new_entry) # Insérer au début de la liste

    # Ne garder que les 100 dernières alertes pour ne pas surcharger
    history = history[:100]

    # Sauvegarder dans le fichier
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f)

    return jsonify({"status": "success"}), 200

# --- MISE À JOUR : ROUTE DES ALERTES ---
@app.route('/alerts')
def alerts_page():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    current_user = session.get('user', {})
    active_alerts = []
    
    # 1. Récupérer les alertes actives en direct
    try:
        api_endpoint = f"{ALERTMANAGER_URL}/api/v2/alerts?active=true&silenced=false&inhibited=false"
        response = requests.get(api_endpoint, timeout=5)
        if response.status_code == 200:
            active_alerts = response.json()
    except Exception as e:
        print(f"Error fetching alerts from Alertmanager: {e}")

    # 2. Charger l'historique depuis le fichier JSON
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        except json.JSONDecodeError:
            pass

    return render_template('alerts.html', user=current_user, alerts=active_alerts, history=history)




# --- NOUVEAU : SAUVEGARDER LE TRIAGE DES ALERTES ---
@app.route('/api/webhook/alerts/triage', methods=['POST'])
def update_alert_triage():
    data = request.json
    index = data.get('index')
    resolution = data.get('resolution')

    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
            
            # Check if the index is valid
            if 0 <= index < len(history):
                # Update the resolution status
                history[index]['resolution'] = resolution
                
                # Save back to the file
                with open(HISTORY_FILE, 'w') as f:
                    json.dump(history, f)
                    
                return jsonify({"status": "success"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "History file not found"}), 404


# --- NOUVEAU : PAGE DE RAPPORTS (REPORTS) ---
@app.route('/reports')
def reports_page():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    current_user = session.get('user', {})
    
    # Load the incident history
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        except json.JSONDecodeError:
            pass

    # Calculate Report Statistics
    stats = {
        'total_events': len(history),
        'critical_alerts': sum(1 for e in history if e.get('severity') == 'critical'),
        'true_positives': sum(1 for e in history if e.get('resolution') == 'resolved'), # Solved
        'false_positives': sum(1 for e in history if e.get('resolution') == 'rejected'), # Rejected
        'pending_investigations': sum(1 for e in history if e.get('resolution', 'pending') in ['pending', 'investigating'])
    }
    
    # Calculate SOC Efficiency (Accuracy rate)
    total_closed = stats['true_positives'] + stats['false_positives']
    stats['accuracy'] = int((stats['true_positives'] / total_closed * 100)) if total_closed > 0 else 0

    # Get only the Critical events for the "Executive Summary"
    critical_events = [e for e in history if e.get('severity') == 'critical']

    return render_template('reports.html', user=current_user, stats=stats, critical_events=critical_events)

# --- LOG ANALYZER ROUTES ---
@app.route('/logs')
def logs_page():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    current_user = session.get('user', {})
    if current_user.get('role') != 'admin':
        return redirect(url_for('dashboard'))
        
    return render_template('logs.html', user=current_user)

@app.route('/api/loki')
def proxy_loki():
    if 'token' not in session or session.get('user', {}).get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    query = request.args.get('query', '{container=~".+"}')
    limit = request.args.get('limit', '100')
    
    try:
        res = requests.get(f"{LOKI_URL}/loki/api/v1/query_range", params={
            'query': query,
            'limit': limit,
            'direction': 'backward'
        }, timeout=5)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 503

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'frontend'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)