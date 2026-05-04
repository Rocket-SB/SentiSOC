# SentiSOC Security Controls

## 1. Identity & Authentication
- **JWT tokens** — HS256 signed, 8-hour expiry, validated on every request
- **Password hashing** — bcrypt with default cost factor
- **Rate limiting** — 10 login attempts/minute per IP (Flask-Limiter)
- **Admin key** — X-Admin-Key header required to create admin accounts via API

## 2. Authorization (RBAC)
Three roles with least-privilege assignment:
- `admin` — full system access
- `user`  — self-service reservations, read resources
- `guest` — read-only view of available resources

Role is embedded in JWT payload and validated server-side on each request.

## 3. Security Logging
Every security event emits a JSON log with tag `[SECURITY]`:
```json
{"tag":"[SECURITY]","event":"LOGIN_FAILURE","user":"bob","ip":"10.0.0.1","details":""}
```
Events logged: USER_REGISTERED, LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT,
               ACCESS_DENIED, ROLE_CHANGED, RESOURCE_CREATED/DELETED,
               RESERVATION_CREATED/CANCELLED, LOAD_SIMULATED

## 4. Container Security
- Multi-stage Docker builds (no build tools in runtime image)
- Non-root user UID 1000 in all containers
- Dropped all Linux capabilities (`capabilities: drop: ["ALL"]`)
- Kubernetes Pod Security Standards: `restricted` profile

## 5. Network Security (Kubernetes)
- Default-deny NetworkPolicy applied to namespace
- Auth service only reachable from frontend + backend tier
- PostgreSQL only reachable from service pods

## 6. CI/CD Security Gates
| Tool      | Purpose                              | Action on Failure |
|-----------|--------------------------------------|-------------------|
| Bandit    | Python SAST (code vulnerabilities)   | Block PR merge    |
| Trivy     | Container CVE scanning               | Block deploy      |
| pip-audit | Dependency vulnerability check       | Warning           |
| pytest    | Functional + security unit tests     | Block PR merge    |

## 7. Monitoring & Detection
- **BruteForceDetected** — Prometheus alert: 5+ failed logins in 1 minute
- **HighErrorRate** — alert when failure rate exceeds 10% over 2 minutes
- **HighCPUUsage** — alert when resource CPU > 80% for 5 minutes
- Grafana dashboard with real-time security metrics
