# SentiSOC — Security Operations Center Platform

A school project demonstrating enterprise security patterns across 3 Python microservices.

## What It Does

SentiSOC is a resource reservation platform that demonstrates:
- **Centralized Auth** — JWT-based login with 3 roles (admin, user, guest)
- **RBAC** — each role sees and can do different things
- **Security Logging** — every login attempt, access denial, and admin action is logged
- **Monitoring** — Prometheus metrics + Grafana dashboards + automated alerts
- **CI/CD Security Gates** — Trivy CVE scanning, Bandit SAST, unit tests

## Quick Start

### Prerequisites
- Docker Desktop
- Docker Compose

### Run locally
```bash
docker-compose up --build
```

| Service            | URL                        |
|--------------------|----------------------------|
| Frontend Dashboard | http://localhost:8080       |
| Auth Service API   | http://localhost:5001       |
| Reservation API    | http://localhost:5002       |
| Resource API       | http://localhost:5003       |
| Grafana            | http://localhost:3000       |
| Prometheus         | http://localhost:9090       |

### Demo Credentials

| Username    | Password   | Role  | Permissions                          |
|-------------|------------|-------|--------------------------------------|
| `admin`     | Admin@123  | admin | Full access, user management         |
| `john_user` | User@123   | user  | Create reservations, view resources  |
| `guest1`    | Guest@123  | guest | View available resources only        |

## Project Structure

```
sentisoc/
├── auth-service/          Flask app — login, register, JWT, RBAC
├── reservation-service/   Flask app — create/cancel reservations
├── resource-service/      Flask app — manage servers/rooms
├── frontend/              Flask app — web dashboard UI
├── monitoring/            Prometheus, Grafana, Alertmanager configs
├── k8s/                   Kubernetes manifests + NetworkPolicies
├── tests/                 Unit tests for auth service
├── scripts/               Test & simulation shell scripts
├── .github/workflows/     GitHub Actions CI/CD pipeline
└── docs/                  Architecture and security docs
```

## Testing Auth & RBAC

```bash
# Run integration test (requires running stack)
./scripts/test-auth-flow.sh http://localhost:5001

# Simulate brute force to trigger alert
./scripts/simulate-brute-force.sh http://localhost:5001
```

## Running Unit Tests

```bash
cd auth-service
pip install -r requirements.txt
pip install pytest pytest-cov
pytest ../tests/ -v
```

## Security Features Demonstrated

1. **JWT Authentication** — RS256-style validation (HS256 for simplicity), 8h expiry
2. **RBAC** — admin/user/guest with enforced permission tiers
3. **Rate Limiting** — 10 login attempts/minute before lockout
4. **Brute Force Detection** — Prometheus alert fires at 5+ failures/minute
5. **Security Logging** — `[SECURITY]` tagged JSON logs for every auth event
6. **Network Policies** — Kubernetes micro-segmentation per service
7. **Pod Security** — non-root UID 1000, dropped Linux capabilities
8. **Multi-stage Docker** — minimal runtime images, no build tools in prod
9. **CI/CD Gates** — Trivy blocks HIGH/CRITICAL CVEs, Bandit catches SAST issues
10. **Metrics Endpoint** — `/metrics` in Prometheus format on each service
