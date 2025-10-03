package io.mosip.openID4VP.authorizationRequest

// For a pre-registered Verifier, the jwksUri is known before the Authorization Request is created itself.
/**
 * Data class representing a trusted Verifier with its details.
 * @param clientId The client identifier of the Verifier.
 * @param responseUris List of valid response URIs for the Verifier.
 * @param jwksUri (Optional) The URI to fetch the JSON Web Key Set (JWKS) for the Verifier, this will be used to verify the signed request objects.
 * @param allowUnsignedRequest (Optional) Flag indicating if the Verifier allows unsigned requests. Default is false.
 */
data class Verifier @JvmOverloads constructor(
    val clientId: String,
    val responseUris: List<String>,
    val jwksUri: String? = null,
    val allowUnsignedRequest: Boolean = false
)