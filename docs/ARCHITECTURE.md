# SentiSOC Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      User Browser                           │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTP :8080
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Frontend Service                         │
│              (Flask, port 8080)                             │
│         Login UI / Dashboard / Admin Panel                  │
└──────────┬──────────────┬──────────────┬────────────────────┘
           │              │              │
     :5001 │        :5002 │        :5003 │
           ▼              ▼              ▼
┌──────────────┐  ┌───────────────┐  ┌────────────────┐
│ Auth Service │  │  Reservation  │  │    Resource    │
│  (Flask)     │  │   Service     │  │    Service     │
│              │  │   (Flask)     │  │    (Flask)     │
│ - Register   │  │               │  │                │
│ - Login/JWT  │  │ - CRUD        │  │ - CRUD         │
│ - RBAC       │  │ - Conflict    │  │ - CPU metrics  │
│ - Rate limit │  │   detection   │  │ - Admin only   │
│ - /metrics   │  │ - /metrics    │  │ - /metrics     │
└──────┬───────┘  └───────┬───────┘  └───────┬────────┘
       │                  │                   │
       └──────────────────┴───────────────────┘
                          │
              SQLite (dev) / PostgreSQL (prod)
```

## Authentication Flow

```
Client          Frontend         Auth Service         JWT
  │                │                   │               │
  │── POST /login ─►                   │               │
  │                │── POST /api/auth/login ──►         │
  │                │                   │─ verify pass  │
  │                │                   │─ generate ───►│
  │                │                   │◄─ JWT token ──│
  │                │◄─── {token} ──────│               │
  │◄── Set session ─                   │               │
  │                                    │               │
  │── GET /dashboard ──►               │               │
  │                │── GET /api/resources ──────────────────►
  │                │   Header: Bearer <token>
  │                │◄── resources data ─────────────────────
  │◄── render page─│
```

## RBAC Permission Matrix

| Endpoint                     | admin | user | guest |
|------------------------------|:-----:|:----:|:-----:|
| POST /api/auth/login         |  ✓    |  ✓   |  ✓    |
| GET  /api/auth/validate      |  ✓    |  ✓   |  ✓    |
| GET  /api/resources          |  ✓    |  ✓   | ✓*    |
| POST /api/resources          |  ✓    |  ✗   |  ✗    |
| GET  /api/reservations       |  ✓    | own  |  ✗    |
| POST /api/reservations       |  ✓    |  ✓   |  ✗    |
| GET  /api/admin/users        |  ✓    |  ✗   |  ✗    |
| PATCH /api/admin/users/role  |  ✓    |  ✗   |  ✗    |
| GET  /api/admin/login-attempts| ✓   |  ✗   |  ✗    |

*guests see only available resources

## Monitoring Architecture

```
Services ──► /metrics ──► Prometheus ──► Grafana Dashboard
                                    └──► Alertmanager ──► Webhook/Email

Key Metrics:
- auth_login_attempts_total{result="success|failure"}
- auth_registered_users_total
- reservations_total{status="active|cancelled"}
- resource_cpu_usage{name="..."}

Alerts:
- BruteForceDetected: failure rate ≥ 5/min  → CRITICAL
- HighErrorRate:       failure% > 10% / 2min → WARNING  
- HighCPUUsage:        cpu > 80% / 5min      → WARNING
```

## CI/CD Security Gates

```
git push → GitHub Actions
    │
    ├── [Gate 1] Bandit SAST         → block on HIGH severity code issues
    ├── [Gate 2] Unit Tests           → block on test failures
    ├── [Gate 3] Build Docker images
    ├── [Gate 4] Trivy CVE scan       → block on HIGH/CRITICAL with fixes
    ├── [Gate 5] pip-audit            → flag vulnerable dependencies
    │
    └── [Deploy] kubectl apply        → only if ALL gates pass
```
