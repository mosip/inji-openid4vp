package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.dto.Verifier

enum class ClientIdScheme(val value: String) {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    DID("did")
}


data class AuthorizationRequest(
    val clientId: String,
    val clientIdScheme: String,
    val responseType: String,
    val responseMode: String?,
    var presentationDefinition: Any,
    val responseUri: String?,
    val redirectUri: String?,
    val nonce: String,
    val state: String,
    var clientMetadata: Any? = null
) {
    init {
        require(presentationDefinition is PresentationDefinition || presentationDefinition is String) {
            "presentationDefinition must be of type String or PresentationDefinition"
        }

        clientMetadata?.let {
            require(clientMetadata is ClientMetadata || clientMetadata is String) {
                "clientMetadata must be of type String or ClientMetadata"
            }
        }
    }

    companion object {

        fun validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: String,
            trustedVerifiers: List<Verifier>,
            setResponseUri: (String) -> Unit,
            shouldValidateClient: Boolean
        ): AuthorizationRequest {

            val queryParameter = extractQueryParameters(
                urlEncodedAuthorizationRequest.substring(
                    urlEncodedAuthorizationRequest.indexOf('?') + 1
                )
            )
            return getAuthorizationRequestObject(
                queryParameter,
                trustedVerifiers,
                shouldValidateClient,
                setResponseUri
            )
        }

        private fun getAuthorizationRequestObject(
            params: MutableMap<String, Any>,
            trustedVerifiers: List<Verifier>,
            shouldValidateClient: Boolean,
            setResponseUri: (String) -> Unit
        ): AuthorizationRequest {
            val authRequestHandler = getAuthorizationRequestHandler(
                params,
                trustedVerifiers,
                setResponseUri,
                shouldValidateClient
            )
            processAndValidateAuthorizationRequestParameter(authRequestHandler)
            return authRequestHandler.createAuthorizationRequestObject()
        }


        private fun processAndValidateAuthorizationRequestParameter(authorizationRequestHandler: ClientIdSchemeBasedAuthorizationRequestHandler) {
            authorizationRequestHandler.validateClientId()
            authorizationRequestHandler.fetchAuthorizationRequest()
            authorizationRequestHandler.setResponseUrlForSendingResponseToVerifier()
            authorizationRequestHandler.validateAndParseRequestFields()
        }

    }
}