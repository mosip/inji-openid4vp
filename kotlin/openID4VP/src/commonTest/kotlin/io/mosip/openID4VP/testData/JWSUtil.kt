package io.mosip.openID4VP.testData

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import io.ipfs.multibase.Multibase
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.nio.charset.StandardCharsets
import java.util.Base64

class JWSUtil {
    companion object {
        private const val ed25519PrivateKey = "7JGq310it2uq1_KZ3kARpoUB36KaVO2Ki5VeqQ_856A"
        private const val didDocumentUrl = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
        private const val publicKeyId = "$didDocumentUrl#key-0"
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
            put("kid", publicKeyId)
        }
        val jwtPayload = mutableMapOf(
            "userId" to "b07f85be",
            "iss" to  "https://mock-verifier.com",
            "exp" to "153452683"
        )

        private fun replaceCharactersInB64(encodedB64: String): String {
            return encodedB64.replace('+', '-')
                .replace('/', '_')
                .replace("=+$".toRegex(), "")
        }

        fun encodeB64(str: String): String {
            val encoded = Base64.getEncoder().encodeToString(str.toByteArray())
            return replaceCharactersInB64(encoded)
        }

        private fun createSignatureED(privateKey: ByteArray, message: String): String {
            val signer = Ed25519Signer()
            val keyParams = Ed25519PrivateKeyParameters(privateKey, 0)
            signer.init(true, keyParams)
            val messageBytes = message.toByteArray(StandardCharsets.UTF_8)
            signer.update(messageBytes, 0, messageBytes.size)
            val signature = signer.generateSignature()
            return replaceCharactersInB64(Base64.getEncoder().encodeToString(signature))
        }

        fun createJWS(
            authorizationRequestParam: Any?,
            addValidSignature: Boolean,
            jwsHeader: JsonObject?
        ): String {
            val mapper = jacksonObjectMapper()
            val header = jwsHeader ?: this.jwtHeader
            val header64 = encodeB64(header.toString())
            val payload64 = encodeB64(mapper.writeValueAsString(authorizationRequestParam))
            val preHash = "$header64.$payload64"
            val privateKey = Base64.getUrlDecoder().decode(ed25519PrivateKey.toByteArray())
            val signature64 = if(addValidSignature)
                createSignatureED(privateKey, preHash)
            else
                "aW52YWxpZC1zaWdu"
            return "$header64.$payload64.$signature64"
        }


        //Method to generate a multibase key for Ed25519
        private fun generateEd25519MultibaseKey(): String {
            // 1. Generate the Ed25519 key pair
            val jwk: OctetKeyPair = OctetKeyPairGenerator(Curve.Ed25519)
                .keyIDFromThumbprint(true)
                .generate()

            // 2. Decode the public key (base64url) into raw bytes
            val rawPubKey = jwk.x.decode() // 32 bytes

            // 3. Prepend multicodec prefix for Ed25519 (0xED 0x01)
            val ed25519Prefix = byteArrayOf(0xED.toByte(), 0x01.toByte())
            val prefixedPubKey = ed25519Prefix + rawPubKey

            // 4. Encode to base58btc using multibase
            val multibasePubKey = Multibase.encode(Multibase.Base.Base58BTC, prefixedPubKey)

            println("z6M-form multibase key: $multibasePubKey")
            return multibasePubKey
        }
    }
}

