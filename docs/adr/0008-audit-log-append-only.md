# ADR-0008: Audit log — append-only, 보안 사고 사후 분석

## 상태
적용

## 배경
보안 사고는 발견 시점보다 발생 시점이 훨씬 빠릅니다 (평균 days~months). 사고가 인지된
후 "그때 무슨 일이 있었나" 를 추적하려면 인증 이벤트의 누적 기록이 필요합니다.

기록 누락이나 사후 변경 가능성이 있는 audit log 는 법무 / 컴플라이언스 / 사고 대응
어디에서도 신뢰받지 못합니다.

## 결정
Append-only audit log. DB 컬럼 / 도메인 객체 / port 모두에서 update / delete 를 허용하지
않습니다.

설계:
- `AuditEvent` (record) — id, tenantId, userId, type, ipAddress, userAgent, payload, occurredAt.
- `AuditEventType` enum — `LOGIN_*`, `MFA_*`, `REFRESH_*`, `SESSION_*`, `ROLE_*` 등.
- `AuditLogRepository` port 는 `append` 단 한 메서드만 노출.
- DB 측에서는 `audit_events` 테이블에 대해 운영 DB role 의 `UPDATE` / `DELETE` 권한을
  회수합니다 (운영 배포 스크립트의 `REVOKE`). 본 단계의 코드 강제는 application 레이어
  까지, DB 측 권한 회수는 운영 플레이북에 둡니다.
- payload 는 자유 형식 JSON (`Map<String,String>`). 평문 비밀번호 / TOTP secret / refresh
  token 평문은 절대 저장 금지 — 호출자가 마스킹 책임을 집니다.

기록 시점:
- `LoginService` — bad credentials / locked / rate limited / 성공 / MFA required
- `VerifyMfaService` — verified / failed
- `RefreshTokenService` — rotated / reuse detected
- `RevokeSessionService` — revoked by user
- `AssignRoleService` — role assigned

## 결과
- 사고 사후 분석 시간 단축 — 사용자별 / IP별 / 이벤트 타입별 시간순 조회 한 쿼리.
- 컴플라이언스 (ISO 27001 A.12.4) 의 변경 불가능한 기록 요건 충족.
- (단점) audit 테이블이 매우 빠르게 자라납니다. 파티셔닝 (월 단위) + 콜드 스토리지 분리가
  후속 작업입니다.
- (단점) audit append 가 호출 트랜잭션 안에 있으면 main 흐름이 audit 실패에 결합되므로
  `REQUIRES_NEW` 로 분리합니다. 단 audit 자체가 실패하면 사고 추적이 불가능해지므로
  audit 실패 알람 / 별도 backup sink (Kafka / S3) 가 후속 작업입니다 (ADR-0012).

## 다시 검토할 시점
- audit 데이터 양이 운영 DB 부담을 주는 시점 → ClickHouse / S3 + Athena 로 외부 sink.
- SIEM 도입 시 → 표준 포맷 (CEF / OCSF) 정렬.

## 용어 풀이 (쉽게)

- **append-only audit log (추가 전용 감사 로그)** — 한 번 적으면 수정·삭제 절대 안 하고 새 줄만 쌓는 장부(은행 통장). 잘못된 게 있어도 지우는 대신 반대 줄을 추가한다. 보안 사고는 한참 뒤에 조사돼 변조 불가능한 기록이 있어야 신뢰받는다.
- **REQUIRES_NEW (트랜잭션 분리)** — 감사 기록을 본 작업(로그인 등)과 '별도 거래'로 떼어내는 설정. 본 작업이 롤백돼도 '시도했다'는 기록은 따로 남고, 감사 기록 실패가 본 작업을 같이 무너뜨리지 않게 한다.
- **SIEM** — 보안 로그를 한곳에 모아 실시간으로 분석·알람하는 보안 관제 도구(Splunk·Elastic 등). 여기로 흘려보내야 '5분 안 100회 실패' 같은 규칙 알람이 돈다.
- **backup sink (백업 적재처)** — DB 외에 Kafka·S3 같은 곳에도 같은 기록을 한 벌 더 흘려두는 안전 사본. 감사 기록 자체가 실패하면 사고 추적이 불가능해져 대비한다.
