package io.mosip.openID4VP.authorizationRequest

// For a pre-registered Verifier, the ClientMetadata is known before the Authorization Request is created itself.
data class Verifier(
    val clientId: String,
    val responseUris: List<String>,
    val jwksUri: String? = null,
    val allowUnsignedRequest: Boolean = false
)