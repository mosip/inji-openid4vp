package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.hashData
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import java.util.Date
import kotlin.collections.get


class UnsignedSdJwtVPTokenBuilder(
    private val clientId: String,
    private val nonce: String,
    private val sdJwtCredentials: List<String>,
) : UnsignedVPTokenBuilder {

    companion object {
        private const val className = "UnsignedSdJwtVPTokenBuilder"
        private const val keyBindingJWT = "kb+jwt"
    }

    override fun build(): Map<String, Any> {
        val uuidToSdJWT = mutableMapOf<String, String>()
        val uuidToUnsignedKBJWT = mutableMapOf<String, String>()

        for (credential in sdJwtCredentials) {
            val uuid = UUIDGenerator.generateUUID()
            uuidToSdJWT[uuid] = credential

            val sdJwt = credential.split("~")[0]
            val sdJwtPayload = JWSHandler.extractDataJsonFromJws(sdJwt, JWSHandler.JwsPart.PAYLOAD)

            val confirmationKeyClaim = sdJwtPayload["cnf"] as? Map<*, *>
                ?: throw InvalidData("cnf missing or empty in sdJWT", className)

            var jwtSigningAlgorithm = ""

            //TODO: What happens if cnf not present?
            if ("kid" in confirmationKeyClaim.keys) {
                val kid = confirmationKeyClaim["kid"] as? String
                    ?: throw InvalidData("kid must be a string", className)
                //TODO: What happens if kid not present?
                val didResolver = DidPublicKeyResolver()
                val confirmationKey = didResolver.resolve(kid, null)
                jwtSigningAlgorithm = extractSigningAlgorithm(confirmationKey as Map<String, Any>)
            }

            val jwtHeader = mapOf(
                "alg" to jwtSigningAlgorithm,
                "typ" to keyBindingJWT
            )

            val sdHashAlgorithm = sdJwtPayload["_sd_alg"] as? String ?: "SHA-256"
            val sdHash = hashData(credential, sdHashAlgorithm)

            val jwtPayload = mapOf(
                "iat" to (Date().time / 1000),
                "aud" to clientId,
                "nonce" to nonce,
                "sd_hash" to sdHash
            )

            val unsignedJwt = JWSHandler.createUnsignedJWS(jwtHeader, jwtPayload)
            uuidToUnsignedKBJWT[uuid] = unsignedJwt
        }

        return mapOf(
            "unsignedVPToken" to UnsignedSdJwtVPToken(uuidToUnsignedKBJWT),
            "vpTokenSigningPayload" to uuidToSdJWT
        )
    }

    private fun extractSigningAlgorithm(confirmationKey: Map<String, Any>): String {
        return confirmationKey["alg"] as? String
            ?: throw InvalidData("alg missing in confirmation key", className)
    }
}
