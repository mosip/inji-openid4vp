package io.mosip.openID4VP.authorizationRequest.proofJwt.handlerFactory

import io.mosip.openID4VP.authorizationRequest.ClientIdScheme
import io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler.DidHandler

object TypeHandlerFactory {
    fun getHandler(clientIdScheme: String): JwtProofTypeHandler? {
        return when (clientIdScheme) {
           ClientIdScheme.DID.value  -> DidHandler()
            else -> null
        }
    }
}