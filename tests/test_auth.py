"""
SentiSOC — Auth Service Unit Tests
Run: pytest tests/ -v
"""
import pytest
import sys
import os

# Add auth-service to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'auth-service'))

from app import app, db, User, LoginAttempt, bcrypt

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SECRET_KEY'] = 'test-secret'

    with app.app_context():
        db.drop_all()   # ensure clean slate (avoids seed-user conflicts)
        db.create_all()
        hashed = bcrypt.generate_password_hash('Test@123').decode('utf-8')
        db.session.add(User(username='testuser', email='test@test.com',
                            password=hashed, role='user'))
        db.session.commit()

    with app.test_client() as c:
        with app.app_context():
            yield c


class TestHealthCheck:
    def test_health_returns_200(self, client):
        r = client.get('/health')
        assert r.status_code == 200
        assert r.json['status'] == 'healthy'


class TestRegistration:
    def test_register_success(self, client):
        r = client.post('/api/auth/register', json={
            'username': 'newuser',
            'email': 'new@test.com',
            'password': 'Pass@123',
            'role': 'user'
        })
        assert r.status_code == 201
        assert 'token' in r.json

    def test_register_duplicate_username(self, client):
        r = client.post('/api/auth/register', json={
            'username': 'testuser',  # already exists
            'email': 'other@test.com',
            'password': 'Pass@123'
        })
        assert r.status_code == 409

    def test_register_missing_fields(self, client):
        r = client.post('/api/auth/register', json={'username': 'x'})
        assert r.status_code == 400

    def test_register_invalid_role(self, client):
        r = client.post('/api/auth/register', json={
            'username': 'x2', 'email': 'x2@test.com',
            'password': 'Pass@123', 'role': 'superuser'
        })
        assert r.status_code == 400


class TestLogin:
    def test_login_success(self, client):
        r = client.post('/api/auth/login', json={
            'username': 'testuser', 'password': 'Test@123'
        })
        assert r.status_code == 200
        assert 'token' in r.json
        assert r.json['user']['role'] == 'user'

    def test_login_wrong_password(self, client):
        r = client.post('/api/auth/login', json={
            'username': 'testuser', 'password': 'wrongpass'
        })
        assert r.status_code == 401
        assert 'error' in r.json

    def test_login_unknown_user(self, client):
        r = client.post('/api/auth/login', json={
            'username': 'ghost', 'password': 'Test@123'
        })
        assert r.status_code == 401


class TestTokenValidation:
    def test_validate_valid_token(self, client):
        # Get a token
        login = client.post('/api/auth/login', json={
            'username': 'testuser', 'password': 'Test@123'
        })
        token = login.json['token']

        r = client.get('/api/auth/validate',
                       headers={'Authorization': f'Bearer {token}'})
        assert r.status_code == 200
        assert r.json['valid'] is True

    def test_validate_no_token(self, client):
        r = client.get('/api/auth/validate')
        assert r.status_code == 401

    def test_validate_invalid_token(self, client):
        r = client.get('/api/auth/validate',
                       headers={'Authorization': 'Bearer fake.token.here'})
        assert r.status_code == 401


class TestRBAC:
    def test_admin_endpoint_rejects_user(self, client):
        # Login as regular user
        login = client.post('/api/auth/login', json={
            'username': 'testuser', 'password': 'Test@123'
        })
        token = login.json['token']

        r = client.get('/api/admin/users',
                       headers={'Authorization': f'Bearer {token}'})
        assert r.status_code == 403  # Forbidden

    def test_metrics_public(self, client):
        r = client.get('/metrics')
        assert r.status_code == 200
        assert b'auth_login_attempts_total' in r.data
