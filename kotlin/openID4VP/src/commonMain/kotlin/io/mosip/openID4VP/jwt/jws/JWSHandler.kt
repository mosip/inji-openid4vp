package io.mosip.openID4VP.jwt.jws

import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.decodeBase64Data
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.*
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64
import java.nio.charset.StandardCharsets

private val className = JWSHandler::class.simpleName!!

class JWSHandler(private val jws: String, private val publicKeyResolver: PublicKeyResolver) {

    enum class JwsPart(val number: Int) {
        HEADER(0),
        PAYLOAD(1),
        SIGNATURE(2)
    }

    fun verify() {
        val verificationResult : Boolean
        try {
            val parts = jws.split(".")
            val header = parts[HEADER.number]
            val payload = parts[PAYLOAD.number]
            val signature = decodeBase64Data(parts[SIGNATURE.number])
            val publicKey = publicKeyResolver.resolveKey(extractDataJsonFromJws(HEADER))
            val publicKeyBytes = Base64.decode(publicKey)
            val publicKeyParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)
            val signer = Ed25519Signer()
            signer.init(false, publicKeyParams)

            val messageBytes = "$header.$payload".toByteArray(StandardCharsets.UTF_8)
            signer.update(messageBytes, 0, messageBytes.size)
            verificationResult = signer.verifySignature(signature)

        } catch (ex: Exception) {
            throw  OpenID4VPExceptions.VerificationFailure("An unexpected exception occurred during verification: ${ex.message}", className)
        }
        if (!verificationResult)
            throw  OpenID4VPExceptions.VerificationFailure("JWS signature verification failed",
                className)
    }

    fun extractDataJsonFromJws(part: JwsPart): MutableMap<String, Any> {
        val components = jws.split(".")
        val payload = components[part.number]
        val decodedString = decodeBase64Data(payload)
        return convertJsonToMap(String(decodedString,Charsets.UTF_8))
    }
}