package io.mosip.openID4VP.jwt

import io.mosip.openID4VP.common.Decoder.decodeBase64Data
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.extractDataJsonFromJwt
import io.mosip.openID4VP.jwt.JwtHandler.JwtPart.*
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64
import java.nio.charset.StandardCharsets

private val className = JwtHandler::class.simpleName!!

class JwtHandler(private val jwt: String, private val publicKeyResolver: PublicKeyResolver) {

    enum class JwtPart(val number: Int) {
        HEADER(0),
        PAYLOAD(1),
        SIGNATURE(2)
    }

    fun verify() {
        val verificationResult : Boolean
        try {
            val parts = jwt.split(".")
            val header = parts[HEADER.number]
            val payload = parts[PAYLOAD.number]
            val signature = decodeBase64Data(parts[SIGNATURE.number])
            val publicKey = publicKeyResolver.resolveKey(extractDataJsonFromJwt(jwt, HEADER))
            val publicKeyBytes = Base64.decode(publicKey)
            val publicKeyParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)
            val signer = Ed25519Signer()
            signer.init(false, publicKeyParams)

            val messageBytes = "$header.$payload".toByteArray(StandardCharsets.UTF_8)
            signer.update(messageBytes, 0, messageBytes.size)
            verificationResult = signer.verifySignature(signature)

        } catch (ex: Exception) {
            throw Logger.handleException(
                exceptionType = "VerificationFailure",
                className = className,
            )
        }
        if (!verificationResult)
            throw Logger.handleException(
                exceptionType = "InvalidSignature",
                className = className,
                message = "JWT signature verification failed"
            )
    }


}