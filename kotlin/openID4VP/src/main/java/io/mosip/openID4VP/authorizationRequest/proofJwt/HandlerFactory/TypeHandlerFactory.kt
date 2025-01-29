package io.mosip.openID4VP.authorizationRequest.proofJwt.HandlerFactory

import DidHandler

enum class ClientIdScheme(val rawValue: String) {
    DID("did")
}

object TypeHandlerFactory {
    fun getHandler(clientIdScheme: String): JwtProofTypeHandler? {
        return when (clientIdScheme) {
           ClientIdScheme.DID.rawValue  -> DidHandler()
            else -> null
        }
    }
}