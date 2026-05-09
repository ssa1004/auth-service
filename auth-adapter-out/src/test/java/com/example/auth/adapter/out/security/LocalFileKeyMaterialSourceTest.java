package com.example.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.port.out.KeyMaterialSource.KeyMaterial;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * LocalFileKeyMaterialSource (ADR-0014) — load/init, rotation 시 previous 슬롯 박제,
 * 부팅 재시작 시 같은 키 복원 여부를 검증.
 */
class LocalFileKeyMaterialSourceTest {

    @Test
    void 처음_부팅_시_새_키_생성_후_저장(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("local-jwk.json");
        LocalFileKeyMaterialSource src = new LocalFileKeyMaterialSource(file);

        KeyMaterial first = src.loadOrInitCurrent();
        assertThat(first.kid()).isNotBlank();
        assertThat(first.keyPair().getPrivate()).isNotNull();
        assertThat(first.keyPair().getPublic()).isNotNull();
        assertThat(file.toFile()).exists();
    }

    @Test
    void 재부팅_시_같은_키_그대로_로드(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("local-jwk.json");
        LocalFileKeyMaterialSource first = new LocalFileKeyMaterialSource(file);
        KeyMaterial original = first.loadOrInitCurrent();

        // 재시작을 시뮬레이트 — 새 인스턴스로 같은 파일 읽기.
        LocalFileKeyMaterialSource second = new LocalFileKeyMaterialSource(file);
        KeyMaterial loaded = second.loadOrInitCurrent();

        assertThat(loaded.kid()).isEqualTo(original.kid());
        assertThat(loaded.keyPair().getPublic().getEncoded())
                .isEqualTo(original.keyPair().getPublic().getEncoded());
    }

    @Test
    void rotate_후_previous_슬롯에_직전_키_박제(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("local-jwk.json");
        LocalFileKeyMaterialSource src = new LocalFileKeyMaterialSource(file);

        KeyMaterial original = src.loadOrInitCurrent();
        assertThat(src.loadPrevious()).isEmpty();

        // 새 키 만들어 회전.
        KeyMaterial newCurrent = anotherKey();
        src.rotate(newCurrent);

        // current 가 newCurrent 로 갱신, previous 가 original 로 박제.
        KeyMaterial reloaded = src.loadOrInitCurrent();
        assertThat(reloaded.kid()).isEqualTo(newCurrent.kid());
        assertThat(src.loadPrevious()).isPresent();
        assertThat(src.loadPrevious().get().kid()).isEqualTo(original.kid());
    }

    private static KeyMaterial anotherKey() throws Exception {
        var gen = java.security.KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return new KeyMaterial(java.util.UUID.randomUUID().toString(), gen.generateKeyPair());
    }
}
