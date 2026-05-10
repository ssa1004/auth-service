#!/usr/bin/env bash
# Portfolio set 통합 시연 스크립트.
#
# 흐름:
#   1) auth-service / resource-server-demo 헬스 대기
#   2) client_credentials 로 access token 발급 (internal-service)
#   3) 그 token 으로 resource server 호출 → 200 검증
#   4) /oauth2/introspect 로 active=true 확인
#   5) admin client 로 /oauth2/revoke 호출 (강제 종료)
#   6) 다시 introspect → active=false 확인
#   7) 다시 resource server 호출 — JWT 자체는 exp 전까지 유효 (서명 OK).
#      revoke 의 즉시 차단 효과는 introspect 기반 검증 / Redis 블록리스트로 확인됨을 안내.
#
# 외부 의존 없음. 모두 docker network 안에서 닫힘.
#
# 실행:
#   docker compose -f infrastructure/docker/docker-compose.integration.yml up -d --build
#   ./scripts/integration-demo.sh

set -euo pipefail

AUTH_BASE="${AUTH_BASE:-http://localhost:8080}"
RS_BASE="${RS_BASE:-http://localhost:9090}"
CLIENT_ID="${CLIENT_ID:-internal-service}"
CLIENT_SECRET="${CLIENT_SECRET:-internal-service-secret-change-me}"
ADMIN_ID="${ADMIN_ID:-internal-admin}"
ADMIN_SECRET="${ADMIN_SECRET:-internal-admin-secret-change-me}"
SCOPE="${SCOPE:-api.read}"
WAIT_SECONDS="${WAIT_SECONDS:-90}"

log()  { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
step() { printf '\n=== %s ===\n' "$*"; }
fail() { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || fail "필수 명령 없음: $1"
}
require curl
require jq

wait_for() {
    local name="$1" url="$2" deadline=$(( $(date +%s) + WAIT_SECONDS ))
    log "[wait] $name 헬스 대기 ($url)"
    while (( $(date +%s) < deadline )); do
        if curl -sf "$url" >/dev/null 2>&1; then
            log "[ok]   $name 응답 OK"
            return 0
        fi
        sleep 2
    done
    fail "$name 가 $WAIT_SECONDS 초 안에 응답하지 않음"
}

# ---------- 1. 헬스 대기 ----------
step "1) 컨테이너 헬스 대기"
wait_for "auth-service"            "$AUTH_BASE/actuator/health/readiness"
wait_for "resource-server-demo"    "$RS_BASE/health"

# ---------- 1.5 JWT decoder 워밍 ----------
# 처음 introspect 는 JWK / RSAPublicKey 초기화로 1~2 초 걸려 lua HTTP timeout 가능.
# 데모용 dummy token 으로 한 번 호출해 cold start 를 미리 흡수.
step "1.5) auth-service JWT decoder warm-up"
curl -s -o /dev/null -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "token=dummy-warmup&token_type_hint=access_token" \
    "$AUTH_BASE/oauth2/introspect" || true
log "[ok]   warm-up 완료"

# ---------- 2. token 발급 ----------
step "2) client_credentials → access token"
TOKEN_RES=$(curl -sf -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "grant_type=client_credentials&scope=$SCOPE" \
    "$AUTH_BASE/oauth2/token") || fail "token 발급 실패"

ACCESS=$(echo "$TOKEN_RES" | jq -r '.access_token')
[[ -n "$ACCESS" && "$ACCESS" != "null" ]] || fail "access_token 파싱 실패: $TOKEN_RES"
log "[ok]   access_token 발급 (앞 16자: ${ACCESS:0:16}...)"
log "       scope=$(echo "$TOKEN_RES" | jq -r '.scope')   exp_in=$(echo "$TOKEN_RES" | jq -r '.expires_in')s"

# ---------- 3. resource server 호출 ----------
step "3) resource server (/api/demo) 호출 — JWT 검증 통과 기대"
RS_RES=$(curl -s -o /tmp/rs.body -w '%{http_code}' \
    -H "Authorization: Bearer $ACCESS" \
    "$RS_BASE/api/demo")
[[ "$RS_RES" == "200" ]] || fail "resource server 호출 실패 status=$RS_RES body=$(cat /tmp/rs.body)"
log "[ok]   200 OK"
jq -r '"       sub=\(.sub)  iss=\(.iss)  scope=\(.scope)"' /tmp/rs.body

# ---------- 4. introspect (active 확인) ----------
step "4) /oauth2/introspect — active=true 기대"
INTRO=$(curl -sf -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "token=$ACCESS&token_type_hint=access_token" \
    "$AUTH_BASE/oauth2/introspect") || fail "introspect 실패"
ACTIVE=$(echo "$INTRO" | jq -r '.active')
[[ "$ACTIVE" == "true" ]] || fail "active=true 기대, got=$INTRO"
log "[ok]   active=true client_id=$(echo "$INTRO" | jq -r '.client_id') exp=$(echo "$INTRO" | jq -r '.exp')"

# ---------- 5. revoke (admin) ----------
step "5) admin client 로 /oauth2/revoke 강제 종료"
REVOKE_HTTP=$(curl -s -o /tmp/revoke.body -w '%{http_code}' \
    -u "$ADMIN_ID:$ADMIN_SECRET" \
    -d "token=$ACCESS&token_type_hint=access_token" \
    "$AUTH_BASE/oauth2/revoke")
# 200 (정상) 또는 500 (client_credentials access JWT 의 subject 가 UUID 가 아니라 audit
# Outcome 매핑이 실패하는 알려진 케이스 — README 후속 작업 참고). 둘 다 Redis 블록리스트
# 추가는 이미 처리된 뒤에 발생하므로 다음 단계에서 active=false 로 검증 가능.
if [[ "$REVOKE_HTTP" == "200" ]]; then
    log "[ok]   RFC 7009 §2.2 응답 200 (body 비어있음)"
elif [[ "$REVOKE_HTTP" == "500" ]]; then
    log "[warn] /oauth2/revoke 가 500 — client_credentials access JWT 의 audit 매핑 알려진 이슈."
    log "       (블록리스트 적재 자체는 예외 직전에 완료됨 — 다음 단계에서 검증)"
else
    fail "revoke 예상 외 status=$REVOKE_HTTP body=$(cat /tmp/revoke.body)"
fi

# ---------- 6. 다시 introspect (active=false) ----------
step "6) revoke 후 다시 introspect — active=false 기대"
INTRO2=$(curl -sf -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "token=$ACCESS&token_type_hint=access_token" \
    "$AUTH_BASE/oauth2/introspect") || fail "introspect2 실패"
ACTIVE2=$(echo "$INTRO2" | jq -r '.active')
[[ "$ACTIVE2" == "false" ]] || fail "active=false 기대, got=$INTRO2"
log "[ok]   active=false (Redis 블록리스트 반영 확인)"

# ---------- 7. resource server 재호출 ----------
step "7) 정보 — JWT self-validation 의 한계"
log "JWT 의 RS256 서명 / exp 만 보면 revoke 후에도 exp 전까지는 통과합니다."
log "강제 종료를 즉시 반영하려면 resource server 가 introspect 를 호출해야 합니다."
log "(README — 'Resource Server 측 introspection 가이드' 참고)"

step "DONE — 통합 시연 완료"
