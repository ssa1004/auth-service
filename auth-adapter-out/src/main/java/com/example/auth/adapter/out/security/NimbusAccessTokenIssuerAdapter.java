package com.example.auth.adapter.out.security;

import com.example.auth.application.port.out.AccessTokenIssuer;
import com.example.auth.application.security.AccessTokenClaims;
import com.example.auth.application.security.AuthProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Nimbus JOSE 로 access JWT 서명. 서명 키는 {@link JwkSourceProvider} 의 current 를 사용.
 *
 * <p>알고리즘: RS256 (ADR-0002 — EdDSA 도입은 후속). header 에 {@code kid} 를 포함시켜야
 * verifier 가 회전 중인 키 중 어느 것으로 검증할지 결정할 수 있습니다.
 */
@Component
@RequiredArgsConstructor
public class NimbusAccessTokenIssuerAdapter implements AccessTokenIssuer {

    private final JwkSourceProvider jwkSourceProvider;
    private final AuthProperties properties;

    @Override
    public String issue(AccessTokenClaims claims) {
        try {
            JWK jwk = jwkSourceProvider.current();
            if (!(jwk instanceof RSAKey rsaKey)) {
                throw new IllegalStateException("현재 JWK 가 RSA 가 아닙니다 — " + jwk.getKeyType());
            }
            JWSSigner signer = new RSASSASigner(rsaKey);

            Instant now = Instant.now();
            JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                    .issuer(properties.jwtIssuer())
                    .subject(claims.userId().asString())
                    .audience(properties.jwtIssuer()) // self-issued, consumer 별 확장 가능
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(claims.ttl())))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("tnt", claims.tenantId().asString())
                    .claim("roles", claims.roles())
                    .claim("permissions", claims.permissions())
                    .claim("amr", claims.amr())
                    .build();

            SignedJWT signed = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .type(JOSEObjectType.JWT)
                            .keyID(rsaKey.getKeyID())
                            .build(),
                    jwtClaims);
            signed.sign(signer);
            return signed.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("access token 서명 실패", e);
        }
    }
}
