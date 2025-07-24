package io.mosip.openID4VP.jwt.jws

import io.ipfs.multibase.Base58
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.*
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec

private val className = JWSHandler::class.simpleName!!


class JWSHandler(private val jws: String, private val publicKeyResolver: PublicKeyResolver) {
    private val provider = BouncyCastleProvider()

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
            val signature = decodeFromBase64Url(parts[SIGNATURE.number])
            val publicKeyMultibase = publicKeyResolver.resolveKey(extractDataJsonFromJws(HEADER))
            val publicKey = getPublicKeyObjectFromPublicKeyMultibase(publicKeyMultibase)
            val messageBytes = "$header.$payload".toByteArray(StandardCharsets.UTF_8)
            verificationResult = ED25519SignatureVerifierImpl().verify(
                publicKey = publicKey,
                signData = messageBytes,
                signature = signature,
                provider = provider
            )
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
        val decodedString = decodeFromBase64Url(payload)
        return convertJsonToMap(String(decodedString,Charsets.UTF_8))
    }

    //TODO: this function exists in vc-verifier.
    private fun getPublicKeyObjectFromPublicKeyMultibase(publicKeyMultibase: String): PublicKey {
        try {
            val rawPublicKeyWithHeader = Base58.decode(publicKeyMultibase.substring(1))
            val rawPublicKey = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
            val publicKey = Hex.decode(DER_PUBLIC_KEY_PREFIX) + rawPublicKey
            val pubKeySpec = X509EncodedKeySpec(publicKey)
            val keyFactory = KeyFactory.getInstance("Ed25519", provider)
            return keyFactory.generatePublic(pubKeySpec)
        } catch (e: Exception) {
            throw PublicKeyNotFoundException("Public key object is null")
        }
    }
}