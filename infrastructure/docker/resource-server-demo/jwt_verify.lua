-- 가상 resource server 의 토큰 검증.
--
-- 본 데모는 RFC 7662 introspection 기반 검증을 사용합니다 — README 의
-- "Resource Server 측 introspection 가이드" 와 동일한 패턴입니다.
--   - JWK 기반 self-validation 도 가능하지만 lua 환경에서 PEM 변환 부담이 커
--     데모는 introspect 단순 호출로 통일.
--   - 응답을 sha256(token) 키로 짧게 캐싱 (TTL=10s) — admin revoke (ADR-0018) 의
--     강제 종료 SLA 와 정합.
--
-- 외부 의존: auth-service 의 /oauth2/introspect (같은 docker network).

local cjson = require "cjson.safe"
local http = require "resty.http"
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"

local AUTH_BASE = os.getenv("AUTH_JWT_ISSUER") or "http://auth:8080"
local INTROSPECT_URI = AUTH_BASE .. "/oauth2/introspect"
local CACHE_TTL = 10
-- 데모 client_credentials — introspect 호출에 client_secret_basic 필요.
local CLIENT_ID = "internal-service"
local CLIENT_SECRET = "internal-service-secret-change-me"

local function hash_token(token)
    local sha = resty_sha256:new()
    sha:update(token)
    return str.to_hex(sha:final())
end

local function deny(status, reason)
    ngx.status = status
    ngx.header["content-type"] = "application/json"
    ngx.say(cjson.encode({error = reason}))
    return ngx.exit(status)
end

local function introspect(token)
    local cache = ngx.shared.jwks_cache
    local key = "introspect:" .. hash_token(token)
    local cached = cache:get(key)
    if cached then
        return cjson.decode(cached)
    end

    local httpc = http.new()
    -- 첫 호출은 auth-service JWT decoder cold-start (JWK 로드 + RSAPublicKey 파싱) 까지
    -- 100~500ms 정도 걸리므로 5초 여유.
    httpc:set_timeout(5000)
    local res, err = httpc:request_uri(INTROSPECT_URI, {
        method = "POST",
        body = "token=" .. ngx.escape_uri(token) .. "&token_type_hint=access_token",
        headers = {
            ["content-type"] = "application/x-www-form-urlencoded",
            ["authorization"] = "Basic " .. ngx.encode_base64(CLIENT_ID .. ":" .. CLIENT_SECRET),
        },
    })
    if not res then
        ngx.log(ngx.ERR, "introspect failed: ", err)
        return nil
    end
    if res.status ~= 200 then
        ngx.log(ngx.WARN, "introspect non-200: ", res.status, " body=", res.body)
        return nil
    end

    cache:set(key, res.body, CACHE_TTL)
    return cjson.decode(res.body)
end

-- 1) Authorization 헤더 추출
local auth = ngx.var.http_authorization
if not auth or not auth:find("^Bearer ") then
    return deny(401, "missing_bearer")
end
local token = auth:sub(8)

-- 2) introspect
local intro = introspect(token)
if not intro then return deny(503, "introspect_unavailable") end

-- 3) active 검증 — RFC 7662
if not intro.active then
    return deny(401, "inactive_token")
end

-- 4) iss 검증 (JWT 자체 iss claim 은 아니나 introspect 응답의 iss 활용)
if intro.iss and intro.iss ~= AUTH_BASE then
    return deny(401, "invalid_issuer")
end

-- 5) scope 검증 (선택) — auth-service 의 introspect 응답은 client_credentials 의 경우
-- scope 를 비워줍니다 (`permissions` 만 매핑). 데모는 강제하지 않고 정보로만 노출.
-- 운영 resource server 에서는 access JWT 를 직접 디코드해 `scope` claim 을 보거나,
-- auth-service 측에서 introspect 응답에 scope 를 추가하도록 보강하는 흐름이 됩니다.
local scope = intro.scope or ""

-- 6) downstream 에서 echo 할 수 있도록 ngx.var 로 노출
ngx.var.jwt_sub = intro.sub or intro.client_id or ""
ngx.var.jwt_scope = scope
ngx.var.jwt_iss = intro.iss or AUTH_BASE
