# ADR-0011: Graceful shutdown — SIGTERM 후 in-flight 요청 보존

## 상태
적용

## 배경
Kubernetes rolling update 또는 스케일 다운 시 K8s 는 컨테이너에 SIGTERM 을 보내고 (기본)
30초 기다린 후 SIGKILL 합니다. 이 사이 처리되어야 할 일:

1. Service endpoint 에서 *이 pod 의 IP 가 빠짐* — 새 요청은 다른 pod 로 흐름.
2. 이미 들어온 (in-flight) 요청은 정상 완료되어야 함.
3. DB / Redis 연결, 스레드 풀 정리.

기본 Spring Boot 는 SIGTERM 받으면 *즉시* shutdown — in-flight 요청이 잘립니다 → 5xx,
사용자에게 "한 번 실패하고 retry 가 통과" 패턴.

추가로 K8s 의 *endpoint 제거 전파* 와 *SIGTERM 전송* 이 거의 동시에 일어납니다 — race 가
있어, 이미 endpoint 에서 빠지기 직전 도달한 요청이 *방금 죽기 시작한* pod 로 떨어질 수
있습니다.

## 결정

### Spring Boot 측 — `server.shutdown=graceful`
- SIGTERM 수신 시 *새 요청은 거부* + *in-flight 요청은 끝까지 처리*.
- `spring.lifecycle.timeout-per-shutdown-phase: 25s` — 25초 안에 끝내지 못하면 강제 종료.
- 25s 는 K8s 의 `terminationGracePeriodSeconds` (30s) 보다 짧게 — 그래야 K8s 가
  SIGKILL 보내기 전에 Spring 이 알아서 정리 끝냄.

### K8s 측
- `terminationGracePeriodSeconds: 30` — preStop 5s + Spring graceful 25s = 30s.
- `lifecycle.preStop.exec.command: ["/bin/sh", "-c", "sleep 5"]` — Service endpoint 가
  빠지는 시간 5초 유격. 이 사이 도달한 요청은 *살아있는 동안의* pod 가 처리.

### 시퀀스
```
t=0  K8s: kill Pod (endpoint 제거 broadcast + preStop 시작)
t=0  preStop: sleep 5s
t=5  K8s: SIGTERM
     Spring: 새 요청 거부, in-flight 처리 계속
t<=30 Spring: 모든 in-flight 처리 완료 → exit 0
t=30 K8s: SIGKILL (만약 Spring 이 아직 안 나갔다면)
```

## 결과
- rolling update 중 5xx 사라짐 (in-flight 요청 보존).
- DB connection / Hikari pool 도 정상 close → 다음 pod 가 풀 가용 충분.

## 다시 검토할 시점
- 평균 요청 시간이 25s 가까워지면 (예: 외부 SSO callback 지연) timeout 재산정.
- SSE / WebSocket 도입 시 별도 graceful drain 정책 필요 — 본 ADR 의 스코프 밖.
