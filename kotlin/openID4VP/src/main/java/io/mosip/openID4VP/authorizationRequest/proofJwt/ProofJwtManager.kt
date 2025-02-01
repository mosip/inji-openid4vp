package io.mosip.openID4VP.authorizationRequest.proofJwt

import io.mosip.openID4VP.authorizationRequest.proofJwt.handlerFactory.TypeHandlerFactory

class ProofJwtManager(
) {
    companion object {
        private val className = ProofJwtManager::class.simpleName ?: "ProofJwtManager"
    }

    fun verifyJWT(jwtToken: String, clientId: String, clientIdScheme: String) {
        val handler = TypeHandlerFactory.getHandler(clientIdScheme)
            ?: throw Exception("InvalidClientIdScheme: Client id scheme in request is invalid (className=$className)")
            handler.verify(jwtToken, clientId)

    }
}