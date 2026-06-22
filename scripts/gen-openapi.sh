#!/usr/bin/env bash
# OpenAPI 3 spec 생성 — 외부 인프라 ZERO.
#
# dev 프로파일(application-dev.yml — H2 in-memory, in-memory rate limiter,
# Redis/SMTP health 비활성)로 앱을 부팅한 뒤, springdoc 이 노출한 /v3/api-docs (JSON)
# 를 받아 `yq` 로 YAML 로 변환해 docs/openapi/auth-service.yaml 로 저장한다.
# Postgres / Redis / Docker 가 필요 없다.
#
# 왜 JSON → yq 변환인가:
#   springdoc 의 native YAML endpoint(/v3/api-docs.yaml)는 SecurityConfig 의 public
#   matcher(/v3/api-docs/**)가 .yaml 형제 경로를 안 덮어 403 이다. permit 된 JSON
#   endpoint(/v3/api-docs)를 받아 변환한다 — e2e OpenApiSpecE2eTest 도 같은 endpoint 검증.
#
# 흐름:
#   1) dev 프로파일로 bootRun (백그라운드) — free high port
#   2) /actuator/health 가 UP(200) 이 될 때까지 polling
#   3) /v3/api-docs (JSON) fetch → yq 로 YAML 변환 → docs/openapi/auth-service.yaml
#   4) 앱 종료 (trap 으로 항상 정리)
#
# 실행:
#   ./scripts/gen-openapi.sh
#   PORT=28080 ./scripts/gen-openapi.sh
#
# CI 의 drift 게이트도 이 스크립트를 호출한다 (.github/workflows/ci.yml).

set -euo pipefail

PORT="${PORT:-18080}"
WAIT_POLLS="${WAIT_POLLS:-150}"   # x2s = 최대 5분
HEALTH_URL="http://localhost:${PORT}/actuator/health"
SPEC_URL="http://localhost:${PORT}/v3/api-docs"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_FILE="$REPO_ROOT/docs/openapi/auth-service.yaml"
LOG_FILE="$(mktemp -t auth-openapi-bootrun.XXXXXX)"

log()  { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }

command -v yq >/dev/null 2>&1 || fail "yq 가 필요합니다 (https://github.com/mikefarah/yq)."

GRADLE_PID=""
cleanup() {
  if [ -n "${GRADLE_PID}" ] && kill -0 "${GRADLE_PID}" 2>/dev/null; then
    log "앱 종료 (pid=${GRADLE_PID})"
    kill "${GRADLE_PID}" 2>/dev/null || true
  fi
  # port 를 아직 잡고 있으면 강제 종료
  local port_pid
  port_pid="$(lsof -tiTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "${port_pid}" ]; then
    sleep 2
    port_pid="$(lsof -tiTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null || true)"
    [ -n "${port_pid}" ] && kill -9 ${port_pid} 2>/dev/null || true
  fi
  rm -f "${LOG_FILE}"
}
trap cleanup EXIT INT TERM

log "dev 프로파일로 bootRun (port=${PORT}) — 로그: ${LOG_FILE}"
( cd "${REPO_ROOT}" && ./gradlew --no-daemon :auth-bootstrap:bootRun \
    --args="--spring.profiles.active=dev --server.port=${PORT}" \
    > "${LOG_FILE}" 2>&1 ) &
GRADLE_PID=$!

log "health 대기 (${HEALTH_URL})"
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' "${HEALTH_URL}" 2>/dev/null)" = "200" ]; do
  i=$((i + 1))
  if [ "${i}" -ge "${WAIT_POLLS}" ]; then
    tail -40 "${LOG_FILE}" >&2 || true
    fail "앱이 ${WAIT_POLLS} polls(=$((WAIT_POLLS * 2))s) 안에 UP 되지 않음."
  fi
  if grep -qiE "APPLICATION FAILED TO START|BUILD FAILED" "${LOG_FILE}" 2>/dev/null; then
    tail -40 "${LOG_FILE}" >&2 || true
    fail "부팅 실패 (로그 참고)."
  fi
  sleep 2
done
log "UP (${i} polls)"

log "spec fetch + YAML 변환 → ${OUT_FILE}"
mkdir -p "$(dirname "${OUT_FILE}")"
curl -fsS "${SPEC_URL}" | yq -P -o=yaml '.' > "${OUT_FILE}" \
  || fail "spec fetch/변환 실패 (${SPEC_URL})."

# 산출물 sanity — openapi/info/paths 가 모두 있어야 함
yq -e '.openapi and .info and .paths' "${OUT_FILE}" >/dev/null \
  || fail "생성된 spec 이 유효한 OpenAPI 3 문서가 아님 (openapi/info/paths 누락)."

log "완료 — paths=$(yq '.paths | length' "${OUT_FILE}"), bytes=$(wc -c < "${OUT_FILE}" | tr -d ' ')"
