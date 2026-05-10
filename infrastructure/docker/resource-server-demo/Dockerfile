# Portfolio set 통합 시연용 가상 resource server.
#
# OpenResty (= nginx + LuaJIT) 위에 lua-resty-http 를 얹어 auth-service 의
# /oauth2/introspect 호출로 access token 의 active / scope / iss 를 검증.
# 다른 7 레포 (resell-orderbook / billing-platform / ...) 의 검증 흐름의 최소 재현 —
# README 의 "Resource Server 측 introspection 가이드" 와 동일한 패턴 (TTL=10s 캐시).
#
# 외부 의존:
#   - auth-service (같은 docker network) 의 /oauth2/introspect
# 외부 API 호출은 없음.
FROM openresty/openresty:1.27.1.1-alpine-fat

# opm 으로 lua-resty-http 설치 (HTTP 클라이언트). lua-resty-string / sha256 은
# OpenResty 기본 bundle 에 포함.
RUN /usr/local/openresty/bin/opm get ledgetech/lua-resty-http

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY jwt_verify.lua /usr/local/openresty/nginx/conf/jwt_verify.lua

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1
