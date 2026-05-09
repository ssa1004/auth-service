package com.example.auth.application.port.out;

import com.example.auth.domain.common.UserId;
import com.example.auth.domain.mfa.MfaSecret;
import java.util.Optional;

public interface MfaSecretRepository {

    MfaSecret save(MfaSecret secret);

    Optional<MfaSecret> findByUser(UserId userId);

    void deleteByUser(UserId userId);
}
