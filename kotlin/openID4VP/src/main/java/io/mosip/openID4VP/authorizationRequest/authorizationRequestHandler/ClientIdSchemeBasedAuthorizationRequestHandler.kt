package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.parseAndValidateClientMetadataInAuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.parseAndValidatePresentationDefinitionInAuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.validateKey
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val className = AuthorizationRequest::class.simpleName!!

abstract class ClientIdSchemeBasedAuthorizationRequestHandler(
    var authorizationRequestParameters: MutableMap<String, Any>,
    val setResponseUri: (String) -> Unit
) {
    var requestUriResponse: Map<String, Any> = emptyMap()

    open fun validateClientId() {
        validateKey(authorizationRequestParameters, CLIENT_ID.value)
    }

    open fun fetchAuthorizationRequest() {
        getStringValue(authorizationRequestParameters, REQUEST_URI.value)?.let {
            if (!isValidUrl(it))
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "$REQUEST_URI data is not valid"
                )
            val requestUriMethod =
                getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value) ?: "get"
            val httpMethod = determineHttpMethod(requestUriMethod)
            requestUriResponse =  sendHTTPRequest(it, httpMethod)
        }
    }

    fun setResponseUrlForSendingResponseToVerifier() {
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value) ?: "fragment"
        val verifierResponseUri = when (responseMode) {
            "direct_post", "direct_post.jwt" -> {
                validateKey(authorizationRequestParameters, RESPONSE_URI.value)
                getStringValue(authorizationRequestParameters, RESPONSE_URI.value)
            }

            else -> throw Logger.handleException(
                exceptionType = "InvalidResponseMode",
                className = className,
                message = "Given response_mode is not supported"
            )
        }
        if (!isValidUrl(verifierResponseUri!!)) {
            throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "$RESPONSE_URI data is not valid"
            )
        }
        setResponseUri(verifierResponseUri)

    }

    open fun validateAndParseRequestFields() {
        validateKey(authorizationRequestParameters, RESPONSE_TYPE.value)
        validateKey(authorizationRequestParameters, NONCE.value)
        validateKey(authorizationRequestParameters, STATE.value)
        parseAndValidateClientMetadataInAuthorizationRequest(authorizationRequestParameters)
        parseAndValidatePresentationDefinitionInAuthorizationRequest(authorizationRequestParameters)
    }

    fun createAuthorizationRequestObject(
    ): AuthorizationRequest {
        return AuthorizationRequest(
            clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!,
            clientIdScheme = getStringValue(authorizationRequestParameters, CLIENT_ID_SCHEME.value)!!,
            responseType = getStringValue(authorizationRequestParameters, RESPONSE_TYPE.value)!!,
            responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value),
            presentationDefinition = authorizationRequestParameters[PRESENTATION_DEFINITION.value]!!,
            responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value),
            redirectUri = getStringValue(authorizationRequestParameters, REDIRECT_URI.value),
            nonce = getStringValue(authorizationRequestParameters, NONCE.value)!!,
            state = getStringValue(authorizationRequestParameters, STATE.value)!!,
            clientMetadata = getStringValue(authorizationRequestParameters, CLIENT_METADATA.value),
        )
    }
}
