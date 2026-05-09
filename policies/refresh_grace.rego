# Refresh token reuse grace window 정책 (ADR-0015 의 도메인 결정 + ADR-0016 의 ABAC).
#
# 도메인 코드 (`RefreshToken.isWithinReuseGrace`) 가 시간 + 같은 IP 두 조건으로 1차 판단을
# 하고, 본 정책이 추가 attribute (예: ASN 화이트리스트, time-of-day) 를 반영합니다.
# 둘 다 grace 라야 grace 처리 — 둘 중 하나라도 reuse 라면 reuse 로 간주 (defense-in-depth).
#
# 입력 context:
#   - sameNetwork:        boolean. 발급 IP 와 호출 IP 가 같은가
#   - secondsSinceRotation: number. 회전 후 경과 초
#   - graceWindowSeconds:   number. 운영자 설정 grace window
#   - ip:                 호출 IP

package auth.refresh.grace

import rego.v1

default allow := false

# 기본 grace 조건 — 같은 네트워크 + 윈도우 안.
allow if {
    input.context.sameNetwork == true
    input.context.secondsSinceRotation <= input.context.graceWindowSeconds
}

reasons contains "different_network" if {
    not allow
    input.context.sameNetwork == false
}

reasons contains "outside_grace_window" if {
    not allow
    input.context.secondsSinceRotation > input.context.graceWindowSeconds
}
