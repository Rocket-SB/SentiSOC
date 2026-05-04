#!/usr/bin/env bash
# ============================================================
# SentiSOC — Auth Flow Integration Test
# Tests all 3 roles and validates RBAC enforcement
# Usage: ./scripts/test-auth-flow.sh [BASE_URL]
# ============================================================

BASE="${1:-http://localhost:5001}"
PASS=0; FAIL=0

green() { echo -e "\033[0;32m✓ $1\033[0m"; ((PASS++)); }
red()   { echo -e "\033[0;31m✗ $1\033[0m"; ((FAIL++)); }
info()  { echo -e "\033[0;36m→ $1\033[0m"; }

check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then green "$desc"; else red "$desc (expected $expected, got $actual)"; fi
}

echo "=================================================="
echo "  SentiSOC Auth Flow Test — $BASE"
echo "=================================================="

# ── Health Check ────────────────────────────────────────
info "Health check"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health")
check "Health endpoint returns 200" "200" "$STATUS"

# ── Role: admin ─────────────────────────────────────────
info "Testing ADMIN role"
RESP=$(curl -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@123"}')
ADMIN_TOKEN=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)
ROLE=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('user',{}).get('role',''))" 2>/dev/null)

check "Admin login succeeds" "admin" "$ROLE"
[ -z "$ADMIN_TOKEN" ] && { red "No admin token received"; exit 1; }

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
check "Admin can access /api/admin/users" "200" "$STATUS"

# ── Role: user ──────────────────────────────────────────
info "Testing USER role"
RESP=$(curl -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"john_user","password":"User@123"}')
USER_TOKEN=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)
ROLE=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('user',{}).get('role',''))" 2>/dev/null)

check "User login succeeds" "user" "$ROLE"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/admin/users" \
  -H "Authorization: Bearer $USER_TOKEN")
check "User CANNOT access admin endpoint (403)" "403" "$STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/auth/validate" \
  -H "Authorization: Bearer $USER_TOKEN")
check "User token validates successfully" "200" "$STATUS"

# ── Role: guest ─────────────────────────────────────────
info "Testing GUEST role"
RESP=$(curl -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"guest1","password":"Guest@123"}')
GUEST_TOKEN=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)
ROLE=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('user',{}).get('role',''))" 2>/dev/null)

check "Guest login succeeds" "guest" "$ROLE"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/admin/users" \
  -H "Authorization: Bearer $GUEST_TOKEN")
check "Guest CANNOT access admin endpoint (403)" "403" "$STATUS"

# ── Invalid credentials ──────────────────────────────────
info "Testing invalid credentials"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrongpassword"}')
check "Bad password returns 401" "401" "$STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/auth/validate" \
  -H "Authorization: Bearer fake.jwt.token")
check "Invalid token returns 401" "401" "$STATUS"

# ── Summary ──────────────────────────────────────────────
echo ""
echo "=================================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "=================================================="
[ $FAIL -eq 0 ] && echo "  ALL TESTS PASSED ✓" || echo "  SOME TESTS FAILED ✗"
