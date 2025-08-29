package io.mosip.openID4VP.jwt.jws

import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.HEADER
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.PAYLOAD
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.SIGNATURE
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolver
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import java.nio.charset.StandardCharsets
import java.security.PublicKey

private val className = JWSHandler::class.simpleName!!


private const val KEY_ID = "kid"

class JWSHandler {
    enum class JwsPart(val number: Int) {
        HEADER(0),
        PAYLOAD(1),
        SIGNATURE(2)
    }

    companion object {
        fun verify(jws: String, publicKeyResolver: PublicKeyResolver, verificationMethodUri: String) {
            val verificationResult : Boolean
            try {
                val keyId = extractDataJsonFromJws(jws, HEADER)[KEY_ID] as? String
                val publicKey: PublicKey = publicKeyResolver.resolve(verificationMethodUri, keyId)

                val parts = jws.split(".")
                val header = parts[HEADER.number]
                val payload = parts[PAYLOAD.number]
                val signature = decodeFromBase64Url(parts[SIGNATURE.number])

                val messageBytes = "$header.$payload".toByteArray(StandardCharsets.UTF_8)
                verificationResult = ED25519SignatureVerifierImpl().verify(
                    publicKey = publicKey,
                    signData = messageBytes,
                    signature = signature,
                    provider = null
                )
            } catch (ex: Exception) {
                throw  OpenID4VPExceptions.VerificationFailure("An unexpected exception occurred during verification: ${ex.message}", className)
            }
            if (!verificationResult)
                throw  OpenID4VPExceptions.VerificationFailure("JWS signature verification failed",
                    className)
        }

        fun extractDataJsonFromJws(jws:String, part: JwsPart): MutableMap<String, Any> {
            val components = jws.split(".")
            val payload = components[part.number]
            val decodedString = decodeFromBase64Url(payload)
            return convertJsonToMap(String(decodedString,Charsets.UTF_8))
        }
    }
}