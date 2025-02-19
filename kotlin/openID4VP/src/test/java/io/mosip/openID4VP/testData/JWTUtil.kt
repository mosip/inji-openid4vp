package io.mosip.openID4VP.testData

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.nio.charset.StandardCharsets
import java.util.Base64

class JWTUtil {
    companion object {
        private const val ed25519PrivateKey = "vlo/0lVUn4oCEFo/PiPi3FyqSBSdZ2JDSBJJcvbf6o0="
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

        fun createJWT(
            authorizationRequestParam: Any?,
            addValidSignature: Boolean,
            jwtHeader: JsonObject?
        ): String {
            val mapper = jacksonObjectMapper()
            val header = jwtHeader ?: this.jwtHeader
            val header64 = encodeB64(header.toString())
            val payload64 = encodeB64(mapper.writeValueAsString(authorizationRequestParam))
            val preHash = "$header64.$payload64"
            val privateKey = Base64.getDecoder().decode(ed25519PrivateKey)
            val signature64 = if(addValidSignature)
                createSignatureED(privateKey, preHash)
            else
                "aW52YWxpZC1zaWdu"
            return "$header64.$payload64.$signature64"
        }
    }
}

