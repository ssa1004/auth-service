# auth-service — 자주 쓰는 명령 단일 진입점 (OAuth2 / OIDC IdP)
#
#   make up        인프라(Postgres / Redis / Mailhog) 기동
#   make ps        컨테이너 상태
#   make logs      인프라 로그 follow
#   make run       auth 서비스 호스트 실행 (:auth-bootstrap bootRun, :8080)
#   make demo      통합 데모 (client_credentials 발급 → 호출 → introspect → revoke)
#   make down      인프라 정지 (볼륨 유지)
#   make clean     인프라 정지 + 볼륨 삭제 (옛 데이터 제거)
#   make build     전체 gradle 빌드 (테스트 제외)
#   make test      전체 검증 (단위 + 통합 + e2e)
#
# 서비스는 호스트에서 ./gradlew :auth-bootstrap:bootRun 으로 띄운다 — Postgres / Redis /
# Mailhog 는 docker compose 로, IdP 본체는 IDE / 호스트에서 디버깅한다. 자세한 건 README "빠른 시작".
# (이 레포는 Kafka 를 쓰지 않는다 — audit SIEM Kafka sink 는 ADR-0012 의 후속 아이디어.)

COMPOSE      := docker compose -f infrastructure/docker/docker-compose.yml
COMPOSE_DEMO := docker compose -f infrastructure/docker/docker-compose.integration.yml
GRADLE       := ./gradlew

.DEFAULT_GOAL := help
.PHONY: help up ps logs run demo load down clean build test urls

help: ## 이 도움말
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

up: ## 인프라 기동 (Postgres / Redis / Mailhog)
	$(COMPOSE) up -d postgres redis mailhog
	@echo "→ Postgres :5432 · Redis :6379 · Mailhog UI http://localhost:8025"

ps: ## 컨테이너 상태
	$(COMPOSE) ps

logs: ## 인프라 로그 follow
	$(COMPOSE) logs -f --tail=100

run: ## auth 서비스 호스트 실행 (:8080) — up 으로 인프라 먼저 띄울 것
	$(GRADLE) :auth-bootstrap:bootRun

demo: ## 통합 데모 (auth + demo RS 기동 → issue → 호출 → introspect → revoke)
	$(COMPOSE_DEMO) up -d --build
	./scripts/integration-demo.sh

load: ## k6 부하 시나리오 (token-issue / introspect / jwks / refresh-reuse)
	./scripts/run-load.sh

down: ## 인프라 정지 (볼륨 유지)
	$(COMPOSE) down

clean: ## 인프라 정지 + 볼륨 삭제 (다음 기동 시 깨끗한 상태)
	$(COMPOSE) down -v

build: ## 전체 gradle 빌드 (테스트 제외)
	$(GRADLE) build -x test

test: ## 전체 검증 (단위 + 통합 + e2e, Postgres + Redis 컨테이너)
	$(GRADLE) check

urls: ## 주요 UI / 엔드포인트
	@echo "OIDC discovery  http://localhost:8080/.well-known/openid-configuration"
	@echo "JWKS            http://localhost:8080/oauth2/jwks"
	@echo "Mailhog UI      http://localhost:8025"
	@echo "auth            :8080 · Postgres :5432 · Redis :6379"
