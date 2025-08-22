package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata

// For a pre-registered Verifier, the ClientMetadata is known before the Authorization Request is created itself.
data class Verifier(val clientId: String, val responseUris: List<String>, val clientMetadata: ClientMetadata? = null)