package io.mosip.openID4VP.authorizationRequest

data class Verifier(val clientId: String, val responseUris: List<String>)