package io.mosip.openID4VP.constants

import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk

enum class RequestSigningAlgorithm(val value: String) {
    EdDSA("EdDSA");

    companion object {
        fun fromValue(value: String): RequestSigningAlgorithm? {
            return entries.find { it.value == value }
        }
    }

    fun matches(jwk: Jwk): Boolean {
        return when (this) {
            EdDSA -> jwk.kty.equals("OKP", ignoreCase = true)
                    && jwk.crv.equals("Ed25519", ignoreCase = true)
        }
    }
}