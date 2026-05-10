# auth-service Helm chart

`auth-service` (OAuth2 / OIDC IdP) 의 Helm chart. 본 레포 `infrastructure/k8s/` 의 raw
manifest 를 chart 형태로 묶어 dev / staging / prod 환경 분기를 values 로 처리합니다.

- chart version: 0.1.0
- app version: 0.1.0
- Helm: 3.x

## 무엇을 묶는가

| template | 조건 |
| --- | --- |
| `deployment.yaml` | 항상 |
| `service.yaml` | 항상 |
| `configmap.yaml` | 항상 |
| `secret.yaml` | `secret.create=true` (기본 true, 운영은 false) |
| `serviceaccount.yaml` | `serviceAccount.create=true` |
| `ingress.yaml` | `ingress.enabled=true` |
| `hpa.yaml` | `autoscaling.enabled=true` |
| `pdb.yaml` | `podDisruptionBudget.enabled=true` |
| `networkpolicy.yaml` | `networkPolicy.enabled=true` |

ConfigMap / Secret 의 checksum 을 pod annotation 에 박아두기 때문에 값을 바꾸면
`helm upgrade` 가 자동으로 rolling restart 를 트리거합니다.

## 설치 / 업그레이드

```bash
# dev — values.yaml 만으로
helm install auth-service ./helm/auth-service \
  --namespace auth --create-namespace

# staging — image tag 만 override
helm upgrade auth-service ./helm/auth-service \
  --namespace auth \
  --set image.tag=staging-abc1234

# prod — values-prod.yaml + 환경별 host override
helm upgrade auth-service ./helm/auth-service \
  --namespace auth \
  --values ./helm/auth-service/values-prod.yaml \
  --set image.tag=v0.1.0 \
  --set ingress.hosts[0].host=auth.your-domain.com \
  --set ingress.tls[0].hosts[0]=auth.your-domain.com
```

## 운영에서의 secret 주입

본 chart 의 `secret.yaml` 은 **dev / 로컬 검증용 placeholder** 입니다. 운영 (prod) 에서는:

1. SealedSecret 또는 ExternalSecret operator 로 `auth-vault-secrets` 같은 Secret 을
   외부 (KMS / Vault) 에서 동기화.
2. `secret.create=false` 로 chart 의 평문 Secret 생성을 끔.
3. `extraEnvFrom` 으로 외부 Secret 을 envFrom 참조 (values-prod.yaml 기본 동작).

```yaml
secret:
  create: false
extraEnvFrom:
  - secretRef:
      name: auth-vault-secrets
```

`auth-vault-secrets` 안에는 다음 키를 채워야 합니다:

- `SPRING_DATASOURCE_USERNAME`, `SPRING_DATASOURCE_PASSWORD`
- `AUTH_MFA_AES_KEY` (32 bytes base64)
- `AUTH_OAUTH2_DEMO_CLIENT_SECRET` (또는 client 별 secret)

## 주요 values 정리

| key | dev 기본 | prod 권장 | 설명 |
| --- | --- | --- | --- |
| `replicaCount` | 2 | 3 | HPA 비활성 시의 고정 replica |
| `image.tag` | `""` (Chart.AppVersion) | release tag | CI 가 `--set` 으로 주입 |
| `resources.limits.cpu` | 1000m | 2000m | |
| `resources.limits.memory` | 1024Mi | 2Gi | |
| `probes.startup.failureThreshold` | 30 | 60 | 운영 인스턴스의 cold start 여유 |
| `terminationGracePeriodSeconds` | 60 | 60 | preStop sleep + Spring graceful 25s + 여유 |
| `preStopSleepSeconds` | 10 | 10 | endpoint 제거 전파 race 흡수 |
| `autoscaling.enabled` | false | true | HPA — cpu 70% / memory 80% |
| `ingress.enabled` | false | true | 운영은 cert-manager + nginx ingress |
| `podDisruptionBudget.enabled` | false | true | minAvailable=1 |
| `networkPolicy.enabled` | false | true | ingress 만 강제 (egress 는 운영자 추가) |
| `auth.jwk.source` | local | kms | 운영은 KMS / Vault 주입 |
| `auth.opa.mode` | embedded | sidecar | sidecar 모드는 OPA 컨테이너가 함께 뜸 |
| `secret.create` | true | false | 운영은 SealedSecret / ExternalSecret |

## ingress path

IdP 가 외부에 노출해야 하는 path 만 선택적으로 엽니다. `values.yaml` / `values-prod.yaml`
의 `ingress.hosts[].paths` 기본값:

- `/oauth2/*` — token / introspect / revoke / jwks
- `/.well-known/*` — OIDC discovery
- `/api/v1/admin/*` — 운영자 endpoint (필요 시 별도 host 로 분리 가능)
- `/actuator/health/*` — LB / 모니터링 health probe

운영자 endpoint 를 별도 host (`auth-admin.example.com`) 로 분리하려면 `ingress.hosts` 를
2개 host 로 나누고 path 를 분배.

## 검증

```bash
helm lint ./helm/auth-service
helm template ./helm/auth-service --values ./helm/auth-service/values-prod.yaml
```

## 의존 서비스

본 chart 는 Postgres / Redis / SMTP 를 묶지 않습니다 — 클러스터에 이미 떠 있다고 가정하고
`config.SPRING_DATASOURCE_URL` / `config.SPRING_DATA_REDIS_URL` 로 endpoint 만 주입합니다.
공식 차트 (bitnami/postgresql, bitnami/redis) 와 함께 운영하는 것을 권장.
