package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition

data class AuthorizationRequest(
    val clientId: String,
    val responseType: String,
    val responseMode: String?,
    var presentationDefinition: PresentationDefinition,
    val responseUri: String?,
    val redirectUri: String?,
    val nonce: String,
    val state: String?,
    var clientMetadata: ClientMetadata? = null,
    val clientIdScheme: String? = null
)  {

    companion object {

        fun validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: String,
            trustedVerifiers: List<Verifier>,
            walletMetadata: WalletMetadata?,
            setResponseUri: (String) -> Unit,
            shouldValidateClient: Boolean
        ): AuthorizationRequest {

            val queryParameter = extractQueryParameters(
                urlEncodedAuthorizationRequest.substring(
                    urlEncodedAuthorizationRequest.indexOf('?') + 1
                )
            )
            return getAuthorizationRequest(
                queryParameter,
                trustedVerifiers,
                walletMetadata,
                shouldValidateClient,
                setResponseUri
            )
        }

        private fun getAuthorizationRequest(
            params: MutableMap<String, Any>,
            trustedVerifiers: List<Verifier>,
            walletMetadata: WalletMetadata?,
            shouldValidateClient: Boolean,
            setResponseUri: (String) -> Unit
        ): AuthorizationRequest {
            val authorizationRequestHandler = getAuthorizationRequestHandler(
                params,
                trustedVerifiers,
                walletMetadata,
                setResponseUri,
                shouldValidateClient
            )
            processAndValidateAuthorizationRequestParameter(authorizationRequestHandler)
            return authorizationRequestHandler.createAuthorizationRequest()
        }


        private fun processAndValidateAuthorizationRequestParameter(authorizationRequestHandler: ClientIdSchemeBasedAuthorizationRequestHandler) {
            authorizationRequestHandler.validateClientId()
            authorizationRequestHandler.fetchAuthorizationRequest()
            authorizationRequestHandler.setResponseUrl()
            authorizationRequestHandler.validateAndParseRequestFields()
        }

    }
}