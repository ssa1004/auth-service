<!--
PR 제목은 Conventional Commits 형식을 따릅니다 (예: feat(application): refresh rotation).
Squash and merge 를 사용하므로 PR 제목이 최종 commit 제목이 됩니다.
-->

## 변경 요약 / Summary

<!-- 무엇을, 왜 바꿨는지 1~3줄로. -->

## 변경 유형 / Type of change

- [ ] feat — 신규 기능
- [ ] fix — 버그 수정
- [ ] refactor — 동작 변화 없는 구조 개선
- [ ] perf — 성능 개선
- [ ] test — 테스트 추가/수정
- [ ] docs — 문서
- [ ] chore / build / ci — 빌드·도구·파이프라인

## 영향 범위 / Affected modules

<!-- 예: domain / application / adapter-out / bootstrap / helm / ci -->

## 검증 / How tested

<!-- 실행한 검증을 구체적으로. 해당되는 항목 체크. -->

- [ ] `./gradlew check` 통과
- [ ] Helm 변경: `helm lint` + `helm template | kubeconform -strict` 통과
- [ ] 워크플로 변경: `actionlint` 통과
- [ ] Dockerfile 변경: `hadolint` 통과

## 체크리스트 / Checklist

- [ ] PR 제목이 Conventional Commits 형식
- [ ] 운영(prod) 동작에 의도치 않은 변화가 없음
- [ ] 비밀/자격증명을 커밋하지 않음
- [ ] 빌드 산출물(build/, *.tgz, rendered-*.yaml)을 커밋하지 않음
- [ ] 필요한 문서(README / ADR)를 갱신함

## 관련 이슈 / Related issues

<!-- Closes #123 -->
