package com.example.auth.adapter.out.security;

import com.example.auth.application.port.out.KeyMaterialSource;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;

/**
 * Dev / local 용 키 소스 (ADR-0014). 디스크 파일 (`local-jwk.json`) 에 RSA 2048 키를
 * 영속화합니다. 파일은 .gitignore 대상.
 *
 * <p>운영 환경에서 절대 사용 금지 — 디스크 휘발 + pod 간 키 불일치 + 시크릿 노출 위험.
 * 운영은 {@code KmsKeyMaterialSource} 로 교체합니다.
 */
@Slf4j
public class LocalFileKeyMaterialSource implements KeyMaterialSource {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path filePath;

    public LocalFileKeyMaterialSource(Path filePath) {
        this.filePath = filePath;
    }

    @Override
    public KeyMaterial loadOrInitCurrent() throws Exception {
        if (Files.exists(filePath)) {
            FileLayout existing = readFile();
            if (existing.current != null) {
                return existing.current.toMaterial();
            }
        }
        // 신규 키 생성 + 저장.
        KeyMaterial fresh = generateKey();
        FileLayout layout = new FileLayout();
        layout.current = SerializedKey.from(fresh);
        writeFile(layout);
        log.info("LocalFileKeyMaterialSource — 신규 키 생성 path={} kid={}", filePath, fresh.kid());
        return fresh;
    }

    @Override
    public Optional<KeyMaterial> loadPrevious() throws Exception {
        if (!Files.exists(filePath)) {
            return Optional.empty();
        }
        FileLayout layout = readFile();
        return Optional.ofNullable(layout.previous).map(SerializedKey::toMaterial);
    }

    @Override
    public void rotate(KeyMaterial newCurrent) throws Exception {
        FileLayout layout = Files.exists(filePath) ? readFile() : new FileLayout();
        layout.previous = layout.current; // current → previous
        layout.current = SerializedKey.from(newCurrent);
        writeFile(layout);
        log.info("LocalFileKeyMaterialSource — 회전 newKid={} previousKid={}",
                newCurrent.kid(),
                layout.previous == null ? "<none>" : layout.previous.kid);
    }

    private KeyMaterial generateKey() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        return new KeyMaterial(UUID.randomUUID().toString(), pair);
    }

    private FileLayout readFile() throws IOException {
        return MAPPER.readValue(filePath.toFile(), FileLayout.class);
    }

    private void writeFile(FileLayout layout) throws IOException {
        Files.createDirectories(filePath.getParent());
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(filePath.toFile(), layout);
    }

    /** json 파일의 layout — current / previous 두 슬롯. */
    public static class FileLayout {
        public SerializedKey current;
        public SerializedKey previous;
    }

    /** RSA 키를 base64 PKCS8 (private) + X509 (public) + kid 로 직렬화. */
    public static class SerializedKey {
        public String kid;
        public String publicKeyB64;
        public String privateKeyB64;

        public static SerializedKey from(KeyMaterial m) {
            SerializedKey s = new SerializedKey();
            s.kid = m.kid();
            s.publicKeyB64 = Base64.getEncoder().encodeToString(m.keyPair().getPublic().getEncoded());
            s.privateKeyB64 = Base64.getEncoder().encodeToString(m.keyPair().getPrivate().getEncoded());
            return s;
        }

        public KeyMaterial toMaterial() {
            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                Map<String, byte[]> raw = new LinkedHashMap<>();
                raw.put("public", Base64.getDecoder().decode(publicKeyB64));
                raw.put("private", Base64.getDecoder().decode(privateKeyB64));
                var pub = kf.generatePublic(new X509EncodedKeySpec(raw.get("public")));
                var priv = kf.generatePrivate(new PKCS8EncodedKeySpec(raw.get("private")));
                return new KeyMaterial(kid, new KeyPair(pub, priv));
            } catch (Exception e) {
                throw new IllegalStateException("local-jwk.json 역직렬화 실패", e);
            }
        }
    }
}
