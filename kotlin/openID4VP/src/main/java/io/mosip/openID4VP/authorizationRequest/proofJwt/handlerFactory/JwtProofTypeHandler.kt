package io.mosip.openID4VP.authorizationRequest.proofJwt.handlerFactory

interface JwtProofTypeHandler {
    fun verify(jwtToken: String, clientId: String)
}