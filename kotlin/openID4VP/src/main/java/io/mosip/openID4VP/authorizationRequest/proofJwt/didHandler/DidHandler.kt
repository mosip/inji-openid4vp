package io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler

import io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler.DidUtils.JwtPart.HEADER
import io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler.DidUtils.JwtPart.PAYLOAD
import io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler.DidUtils.JwtPart.SIGNATURE
import io.mosip.openID4VP.authorizationRequest.proofJwt.handlerFactory.JwtProofTypeHandler
import io.mosip.openID4VP.common.isJWT
import io.mosip.openID4VP.common.makeBase64Standard
import io.mosip.openID4VP.exception.JWTVerificationException
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64
import java.nio.charset.StandardCharsets

class DidHandler : JwtProofTypeHandler {
    companion object {
        private val className = DidHandler::class.simpleName ?: "DidHandler"
        private const val RESOLVER_API = "https://resolver.identity.foundation/1.0/identifiers/"
    }

    //TODO: clientId domain name may not be specific to DidHandler, should it be named as didUrl
    override fun verify(jwtToken: String, clientId: String) {
        val url = "$RESOLVER_API${clientId}"
        val didResponse = sendHTTPRequest(url, HTTP_METHOD.GET)
        if (!isJWT(jwtToken)) {
            throw throw JWTVerificationException.InvalidJWT()
        }
        val kid = DidUtils.extractKid(jwtToken)
            ?: throw JWTVerificationException.KidExtractionFailed("KidExtractionFailed: KID extraction from DID document failed (className=$className)")

        val publicKey = DidUtils.extractPublicKeyMultibase(kid, didResponse)
            ?: throw JWTVerificationException.PublicKeyExtractionFailed("PublicKeyExtractionFailed: Public key extraction failed (className=$className)")

        verifyJWT(jwtToken, publicKey)

    }

    private fun verifyJWT(jwt: String, publicKey: String) {
        val parts = jwt.split(".")
        val header = parts[HEADER.number]
        val payload = parts[PAYLOAD.number]
        val signature = Base64.decode(makeBase64Standard(parts[SIGNATURE.number]))

        val publicKeyBytes = Base64.decode(publicKey)
        val publicKeyParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)

        val signer = Ed25519Signer()
        signer.init(false, publicKeyParams)

        val messageBytes = "$header.$payload".toByteArray(StandardCharsets.UTF_8)
        signer.update(messageBytes, 0, messageBytes.size)

        val verificationResult: Boolean = signer.verifySignature(signature)
        if (!verificationResult)
            throw JWTVerificationException.InvalidSignature("JWT signature verification failed (className=$className)")
    }
}