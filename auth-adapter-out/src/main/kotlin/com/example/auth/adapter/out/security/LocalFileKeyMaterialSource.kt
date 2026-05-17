package com.example.auth.adapter.out.security

import com.example.auth.application.port.out.KeyMaterialSource
import com.example.auth.application.port.out.KeyMaterialSource.KeyMaterial
import com.fasterxml.jackson.databind.ObjectMapper
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Optional
import java.util.UUID
import org.slf4j.LoggerFactory

/**
 * Dev / local 용 키 소스 (ADR-0014). 디스크 파일 (`local-jwk.json`) 에 RSA 2048 키를
 * 영속화합니다. 파일은 .gitignore 대상.
 *
 * 운영 환경에서 절대 사용 금지 — 디스크 휘발 + pod 간 키 불일치 + 시크릿 노출 위험.
 * 운영은 [KmsKeyMaterialSource] 로 교체합니다.
 */
class LocalFileKeyMaterialSource(private val filePath: Path) : KeyMaterialSource {

    override fun loadOrInitCurrent(): KeyMaterial {
        if (Files.exists(filePath)) {
            val existing = readFile()
            existing.current?.let { return it.toMaterial() }
        }
        // 신규 키 생성 + 저장.
        val fresh = generateKey()
        val layout = FileLayout()
        layout.current = SerializedKey.from(fresh)
        writeFile(layout)
        log.info("LocalFileKeyMaterialSource — 신규 키 생성 path={} kid={}", filePath, fresh.kid)
        return fresh
    }

    override fun loadPrevious(): Optional<KeyMaterial> {
        if (!Files.exists(filePath)) {
            return Optional.empty()
        }
        val layout = readFile()
        return Optional.ofNullable(layout.previous?.toMaterial())
    }

    override fun rotate(newCurrent: KeyMaterial) {
        val layout = if (Files.exists(filePath)) readFile() else FileLayout()
        layout.previous = layout.current // current → previous
        layout.current = SerializedKey.from(newCurrent)
        writeFile(layout)
        log.info(
            "LocalFileKeyMaterialSource — 회전 newKid={} previousKid={}",
            newCurrent.kid,
            layout.previous?.kid ?: "<none>",
        )
    }

    private fun generateKey(): KeyMaterial {
        val gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(2048)
        val pair = gen.generateKeyPair()
        return KeyMaterial(UUID.randomUUID().toString(), pair)
    }

    private fun readFile(): FileLayout = MAPPER.readValue(filePath.toFile(), FileLayout::class.java)

    private fun writeFile(layout: FileLayout) {
        Files.createDirectories(filePath.parent)
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(filePath.toFile(), layout)
    }

    /** json 파일의 layout — current / previous 두 슬롯. */
    class FileLayout {
        @JvmField var current: SerializedKey? = null
        @JvmField var previous: SerializedKey? = null
    }

    /** RSA 키를 base64 PKCS8 (private) + X509 (public) + kid 로 직렬화. */
    class SerializedKey {
        @JvmField var kid: String? = null
        @JvmField var publicKeyB64: String? = null
        @JvmField var privateKeyB64: String? = null

        fun toMaterial(): KeyMaterial {
            return try {
                val kf = KeyFactory.getInstance("RSA")
                val pub = kf.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyB64)))
                val priv = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyB64)))
                KeyMaterial(kid!!, KeyPair(pub, priv))
            } catch (e: Exception) {
                throw IllegalStateException("local-jwk.json 역직렬화 실패", e)
            }
        }

        companion object {
            @JvmStatic
            fun from(m: KeyMaterial): SerializedKey = SerializedKey().apply {
                kid = m.kid
                publicKeyB64 = Base64.getEncoder().encodeToString(m.keyPair.public.encoded)
                privateKeyB64 = Base64.getEncoder().encodeToString(m.keyPair.private.encoded)
            }
        }
    }

    private companion object {
        val MAPPER = ObjectMapper()
        val log = LoggerFactory.getLogger(LocalFileKeyMaterialSource::class.java)
    }
}
