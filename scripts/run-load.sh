#!/usr/bin/env bash
# k6 부하 시나리오 일괄 실행.
#
# 흐름:
#   1) auth-service 헬스 대기
#   2) USER_EMAIL 사용자 사전 register (이미 있으면 409 무시)
#   3) 시나리오 순차 실행 — 모두 통과 시 0, 하나라도 threshold 위반 시 nonzero
#
# 환경 변수 (load/k6/lib/config.js 와 동일):
#   BASE_URL, CLIENT_ID, CLIENT_SECRET, TENANT_SLUG, USER_EMAIL, USER_PASSWORD
#
# 실행:
#   ./scripts/run-load.sh
#   BASE_URL=http://localhost:8080 ./scripts/run-load.sh

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TENANT_SLUG="${TENANT_SLUG:-acme}"
USER_EMAIL="${USER_EMAIL:-alice@example.com}"
USER_PASSWORD="${USER_PASSWORD:-longenoughpw1234}"
WAIT_SECONDS="${WAIT_SECONDS:-90}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
K6_DIR="$REPO_ROOT/load/k6"

log()  { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
step() { printf '\n=== %s ===\n' "$*"; }
fail() { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || fail "필수 명령 없음: $1"; }
require curl
require k6

wait_for() {
    local url="$1" deadline=$(( $(date +%s) + WAIT_SECONDS ))
    log "[wait] auth-service 헬스 대기 ($url)"
    while (( $(date +%s) < deadline )); do
        if curl -sf "$url" >/dev/null 2>&1; then
            log "[ok]   응답 OK"
            return 0
        fi
        sleep 2
    done
    fail "auth-service 가 $WAIT_SECONDS 초 안에 응답하지 않음"
}

ensure_user() {
    local status
    # 409 (이미 등록) 는 정상. 201 도 정상. 그 외는 실패.
    status=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST "$BASE_URL/api/v1/auth/register" \
        -H 'Content-Type: application/json' \
        -d "{\"tenantSlug\":\"$TENANT_SLUG\",\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}")
    case "$status" in
        201) log "[ok]   user registered ($USER_EMAIL)";;
        409) log "[ok]   user already exists ($USER_EMAIL)";;
        *)   fail "register 예상 외 status=$status";;
    esac
}

run_scenario() {
    local name="$1"
    step "k6 run $name"
    k6 run "$K6_DIR/scenarios/$name"
}

step "1) auth-service 헬스 대기"
wait_for "$BASE_URL/actuator/health/readiness"

step "2) /auth/login fixture 사용자 보장"
ensure_user

step "3) k6 시나리오 일괄 실행"
run_scenario "token-issue.js"
run_scenario "token-introspect.js"
run_scenario "jwks-fetch.js"
run_scenario "login-refresh.js"
run_scenario "refresh-reuse-detection.js"

step "DONE — 모든 시나리오 threshold 통과"
