package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = VPResponseMetadata::class.simpleName!!

@Deprecated("This class is deprecated and will be removed in future versions.")
data class VPResponseMetadata(
    val jws: String,
    val signatureAlgorithm: String,
    val publicKey: String,
    val domain: String,
)  {
    fun validate() {
        val requiredParams = mapOf(
            "jws" to this.jws,
            "signatureAlgorithm" to this.signatureAlgorithm,
            "publicKey" to this.publicKey,
            "domain" to this.domain,
        )

        requiredParams.forEach { (key, value) ->
            require(value != "null" && validateField(value, "String")) {
                throw OpenID4VPExceptions.InvalidInput(listOf("ldp_vp_token_signing_result", key),key::class.simpleName, className)
            }
        }
    }
}