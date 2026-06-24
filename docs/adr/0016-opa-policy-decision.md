# ADR-0016: OPA (Open Policy Agent) 기반 ABAC 정책 엔진 도입

## 상태
적용

## 배경

ADR-0005 에서 본 IdP 의 권한 모델은 RBAC (역할 기반 접근 제어) 으로 시작했다. JWT claim
의 `roles[]` 가 핵심 결정 기준. 단순한 권한 (예: "운영자 role 가 admin endpoint 호출")
에는 충분하다.

문제: 운영이 진행되면서 *상황별 동적 정책* 이 늘어난다.

- **본인 자원만** — alice 가 *자기* 다른 디바이스 세션 revoke 는 OK, bob 의 세션은 X
- **테넌트 격리** — workspace A 의 admin 은 workspace B 의 사용자를 못 본다
- **중첩 권한** — admin role 부여는 *senior admin* 만 (admin 이 admin 을 못 만들음)
- **시간 / 네트워크 조건** — refresh reuse grace 는 *5초 안 + 같은 IP* 만 허용

이런 정책들이 코드 곳곳의 `if (caller.isAdmin() || caller.id().equals(target.ownerId()))`
로 흩어지면:

- 정책 변경 시 *코드 수정 + 재배포* 필요 — 보안 정책은 운영 중에 자주 바뀌는데 배포 리드
  타임이 길어 사고 발생
- 정책이 코드 곳곳에 흩어져 *전체 권한 모델* 을 한 번에 보기 어렵다 → 감사 누락 위험
- 같은 정책이 여러 endpoint 에 반복 — 일관성 깨짐

해결책은 **정책을 코드 밖으로 분리** — 정책 결정만 담당하는 별도 엔진 (PDP — Policy
Decision Point) 을 두고, 코드는 그 엔진을 호출만 한다.

OPA (Open Policy Agent) 는 이 패턴의 사실상의 표준이다. Cloud Native Computing
Foundation graduated 프로젝트이며 Kubernetes admission control / Istio service mesh /
Terraform plan 검증 등에 광범위하게 쓰인다.

## 결정

### Rego 정책 파일 — 코드 밖

`policies/` 디렉토리에 `.rego` 파일 4개:

```
policies/
├── session_management.rego   # 본인 세션만 revoke / list
├── tenant_isolation.rego     # cross-tenant 접근 차단
├── role_assignment.rego      # senior_admin 만 admin 부여
└── refresh_grace.rego        # ADR-0015 의 grace window 정책 표현
```

각 정책은 입력 (`input.subject`, `input.action`, `input.resource`, `input.context`) 을
받아 `allow` (boolean) + `reasons` (string[]) 를 반환한다. 예시 (`session_management.rego`):

```rego
package auth.session

default allow = false

allow {
    input.action == "session.revoke"
    input.subject.id == input.resource.ownerId
    reasons := ["self_resource"]
}

allow {
    input.action == "session.revoke"
    "admin" in input.subject.roles
    reasons := ["admin_role"]
}
```

코드 변경 없이 정책만 수정 → 재배포 (또는 hot reload) 만으로 권한 모델 변경.

### 두 모드 — embedded / sidecar

```yaml
auth:
  opa:
    mode: ${AUTH_OPA_MODE:embedded}   # embedded | sidecar
    sidecar-url: ${AUTH_OPA_URL:http://localhost:8181}
    bundle-path: ${AUTH_OPA_BUNDLE:classpath:policies}
```

**embedded** (dev / 작은 운영):
- 정책 파일을 classpath 또는 디스크에서 로드
- 단순 in-process 평가 (Rego 의 단순 표현만 — `allow if X and Y`, `default allow = false`,
  `in` operator). 복잡한 Rego 기능은 sidecar 권장
- 외부 의존성 0 — 단일 jar 로 끝

**sidecar** (prod):
- K8s pod 안 OPA 데몬 (`openpolicyagent/opa:latest`) 을 sidecar 로 띄우고
  `http://localhost:8181/v1/data/<package>` 호출
- OPA 가 bundle distribution 으로 정책 git repo / S3 에서 자동 polling → hot reload
- decision log 도 OPA 가 직접 Kafka / S3 로 sink

dev / 단위 테스트는 embedded 로 가볍게, prod 는 sidecar 로 운영 표준에 맞춤.

### Decision log → AuditEntry

모든 정책 평가 결과를 `audit_entries` 에 한 줄씩 기록한다.

```
type=POLICY_DECISION_ALLOW
payload={policyPath: "auth/session/revoke", action: "session.revoke",
         subject: "alice@workspace1", resource: "session-uuid",
         allow: "true", reasons: "self_resource"}
```

용도:
- ISMS-P 2.9 (감사 로그) — *누가 무엇을 시도했고 왜 허용 / 거부됐는지* 영구 기록
- 사후 사고 분석 — "왜 alice 가 bob 의 세션을 revoke 할 수 있었는가" 의 결정 trail
- 정책 회귀 검증 — 정책 변경 후 deny → allow 로 바뀐 케이스 자동 추출

### Fail-closed — 평가 실패는 deny

OPA 호출 자체가 실패 (네트워크 / 정책 syntax error / 타임아웃) 하면 `denied("policy_evaluation_error")`.
*권한이 불확실하면 거절* 이 보안 표준. 정책 엔진 장애가 권한 우회로 이어지지 않게.

## 대안

### Spring Security 의 `@PreAuthorize` SpEL
탈락 — SpEL 식이 코드에 박혀 있어 정책 외부화 효과 없음. 또 SpEL 로는 복잡 정책 표현이 어렵고
여러 endpoint 에서 같은 정책을 반복해야 한다.

### Casbin
검토했으나 선택 X — RBAC 표현은 강하지만 ABAC / 시간 / 네트워크 조건 같은 *임의 속성 조합*
표현력은 OPA / Rego 가 더 풍부하다. Casbin 의 PERM 모델은 단순한 권한 매트릭스에 적합.

### 자체 DSL
탈락 — *정책 언어를 새로 만들면* 우리만 알고 외부 운영자 / 보안팀이 학습 곤란. OPA / Rego 는
업계 표준이라 외부 인력의 진입 장벽이 낮다.

## 결과

- 정책이 코드 밖으로 분리 — 정책 변경에 재배포가 필요 없는 경로 (sidecar + bundle) 확보
- 모든 권한 결정이 audit_entries 에 일관 기록 — ISMS-P / SOX / PCI-DSS 감사 대응
- embedded 모드로 dev 진입 장벽 0 — 단위 테스트는 OPA 데몬 없이 가능
- defense-in-depth — RBAC (1차, JWT claim) → ABAC (2차, OPA) 두 단계
- (단점) Rego 학습 곡선 — 운영자 / 신규 개발자가 익숙해지는 데 시간 필요. 본 ADR 의 정책 4개는
  단순 패턴 위주로 *예시 + 주석* 충실히 작성
- (단점) embedded 모드는 Rego 일부만 지원 — 복잡 정책은 sidecar 강제. 그 경계는 정책 헤더의
  주석에 명시
- (단점) decision log 가 매 권한 호출마다 INSERT — 트래픽 큰 endpoint 는 audit batch 또는
  비동기 처리 검토. 본 ADR 범위 밖

## 후속

- ADR (예정): OPA bundle 자동 배포 — 정책 git repo + S3 + OPA polling
- ADR (예정): 정책 회귀 테스트 — 정책 변경 시 decision log 가 deny → allow 로 바뀐 케이스 자동 검출
- ADR (예정): Token Introspection (RFC 7662) + Token Revocation (RFC 7009) — admin 이 즉시 revoke 가능한 endpoint

## 용어 풀이 (쉽게)

- **OPA (Open Policy Agent)** — 권한 판단 규칙을 코드 밖 별도 파일로 빼서, 코드는 'OPA야 이거 허용해도 돼?'라고 묻기만 하게 해주는 표준 정책 엔진. 규칙이 바뀌어도 코드 재배포 없이 정책 파일만 고치면 된다.
- **Rego** — OPA가 쓰는 규칙 전용 언어. if문을 코드 곳곳에 흩뿌리는 대신 '본인 자원이면 허용, admin이면 허용' 같은 규칙을 이 언어로 한곳에 모아 쓴다.
- **PDP (Policy Decision Point, 정책 결정 창구)** — '허용/거부'만 전담으로 답하는 단일 심판 창구. 권한 판단을 한 곳에 모아 전체 권한 모델을 한눈에 보고 감사하기 쉽게 한다.
- **embedded vs sidecar** — embedded는 정책 엔진을 앱 안에 같이 넣어 가볍게 돌리는 방식(외부 의존 0), sidecar는 같은 pod 옆에 OPA 데몬을 따로 띄워 정책을 git/S3에서 자동으로 받아 갱신(hot reload)하는 운영용 방식.
- **fail-closed (실패 시 거부)** — 정책 엔진이 고장(끊김·문법 오류·타임아웃)나면 일단 '거부'로 처리하는 안전 원칙. '확실하지 않으면 문을 잠근다'. 정책 장애가 권한 우회로 번지지 않게 한다.
- **defense-in-depth (다중 방어)** — 방어선을 한 겹만 두지 않고 RBAC(1차, 토큰 claim) → ABAC/OPA(2차) 처럼 여러 겹을 쌓는 것. 한 겹이 뚫려도 다음 겹이 막는다.
