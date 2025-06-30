package io.mosip.openID4VP.jwt.jwe

import com.nimbusds.jose.JWEHeader
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.jwt.jwe.encryption.EncryptionProvider
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = JWEHandler::class.simpleName!!

class JWEHandler(
    private val keyEncryptionAlg: String,
    private val contentEncryptionAlg: String,
    private val publicKey: Jwk,
    private val walletNonce: String,
    private val verifierNonce: String
) {

    fun generateEncryptedResponse(payload: Map<String, Any>): String {

        val encrypter = EncryptionProvider.getEncrypter(publicKey)

        val headerMap = mapOf(
            "alg" to keyEncryptionAlg,
            "enc" to contentEncryptionAlg,
            "kid" to publicKey.kid,
            "apu" to walletNonce,
            "apv" to verifierNonce
        )
        val header = JWEHeader.parse(headerMap)

        val claimsSet = JWTClaimsSet.Builder().apply {
            payload.forEach { (key, value) -> claim(key, value) }
        }.build()

        try {
            val jwt = EncryptedJWT(header, claimsSet)
            jwt.encrypt(encrypter)
            return jwt.serialize()
        } catch (exception: Exception) {
            throw  OpenID4VPExceptions.JweEncryptionFailure(className)
        }
    }
}