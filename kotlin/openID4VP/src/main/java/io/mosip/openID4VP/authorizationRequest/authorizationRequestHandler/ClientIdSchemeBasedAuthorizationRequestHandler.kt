package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.parseAndValidateClientMetadata
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.parseAndValidatePresentationDefinition
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.extractClientIdScheme
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = ClientIdSchemeBasedAuthorizationRequestHandler::class.simpleName!!

abstract class ClientIdSchemeBasedAuthorizationRequestHandler(
    var authorizationRequestParameters: MutableMap<String, Any>,
    val walletMetadata: WalletMetadata?,
    private val setResponseUri: (String) -> Unit
) {
    protected var shouldValidateWithWalletMetadata = false

    open fun validateClientId() {
        return
    }

    fun fetchAuthorizationRequest() {
        var requestUriResponse: Map<String, Any> = emptyMap()
        getStringValue(authorizationRequestParameters, REQUEST_URI.value)?.let { requestUri ->
            if (!isValidUrl(requestUri))
                throw OpenID4VPExceptions.InvalidData("${REQUEST_URI.value} data is not valid", className)
            val requestUriMethod =
                getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value) ?: "get"
            val httpMethod = try {
                determineHttpMethod(requestUriMethod)
            } catch (e: IllegalArgumentException) {
                throw OpenID4VPExceptions.InvalidData("Unsupported HTTP method: $requestUriMethod", className, OpenID4VPErrorCodes.INVALID_REQUEST_URI_METHOD)
            }

            var body: Map<String, String>? = null
            var headers: Map<String, String>? = null


            if (httpMethod == HttpMethod.POST) {
                walletMetadata?.let { walletMetadata ->
                    isClientIdSchemeSupported(walletMetadata)
                    val processedWalletMetadata = process(walletMetadata)
                    body = mapOf(
                        "wallet_metadata" to
                            encodeToJsonString<WalletMetadata>(processedWalletMetadata, "wallet_metadata", className),

                    )
                    headers = getHeadersForAuthorizationRequestUri()
                    shouldValidateWithWalletMetadata = true
                }
            }
            requestUriResponse = sendHTTPRequest(requestUri, httpMethod, body, headers)

        }
        this.validateRequestUriResponse(requestUriResponse)
    }

    abstract fun validateRequestUriResponse(
        requestUriResponse: Map<String, Any>
    )

    abstract fun process(walletMetadata: WalletMetadata): WalletMetadata

    abstract  fun getHeadersForAuthorizationRequestUri(): Map<String, String>

    fun setResponseUrl() {
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value)
            ?: throw  OpenID4VPExceptions.MissingInput(listOf(RESPONSE_MODE.value),"", className)
        ResponseModeBasedHandlerFactory.get(responseMode)
            .setResponseUrl(authorizationRequestParameters, setResponseUri)
    }

    open fun validateAndParseRequestFields() {
        val responseType = getStringValue(authorizationRequestParameters, RESPONSE_TYPE.value)
        validate(RESPONSE_TYPE.value, responseType, className)
        val nonce = getStringValue(authorizationRequestParameters, NONCE.value)
        validate(NONCE.value, nonce, className)
        val state = getStringValue(authorizationRequestParameters, STATE.value)
        state?.let {
            validate(STATE.value, state, className)
        }
        parseAndValidateClientMetadata(authorizationRequestParameters, shouldValidateWithWalletMetadata, walletMetadata)
        val presentationDefinitionUriSupported = !shouldValidateWithWalletMetadata ||
                walletMetadata?.presentationDefinitionURISupported ?: true
        parseAndValidatePresentationDefinition(authorizationRequestParameters, presentationDefinitionUriSupported)
    }

    private fun isClientIdSchemeSupported(walletMetadata: WalletMetadata) {
        val clientIdScheme = extractClientIdScheme(authorizationRequestParameters)
        if (!walletMetadata.clientIdSchemesSupported.contains(clientIdScheme))
            throw OpenID4VPExceptions.InvalidData("client_id_scheme is not support by wallet", className)

    }

    fun createAuthorizationRequest(): AuthorizationRequest {
        return AuthorizationRequest(
            clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!,
            responseType = getStringValue(authorizationRequestParameters, RESPONSE_TYPE.value)!!,
            responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value),
            presentationDefinition = authorizationRequestParameters[PRESENTATION_DEFINITION.value] as PresentationDefinition,
            responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value),
            redirectUri = getStringValue(authorizationRequestParameters, REDIRECT_URI.value),
            nonce = getStringValue(authorizationRequestParameters, NONCE.value)!!,
            state = getStringValue(authorizationRequestParameters, STATE.value),
            clientMetadata = authorizationRequestParameters[CLIENT_METADATA.value] as? ClientMetadata,
            clientIdScheme = getStringValue(authorizationRequestParameters, CLIENT_ID_SCHEME.value)
        )
    }

}
