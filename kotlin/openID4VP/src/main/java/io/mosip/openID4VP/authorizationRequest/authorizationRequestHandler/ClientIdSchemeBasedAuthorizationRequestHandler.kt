package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.parseAndValidateClientMetadata
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.parseAndValidatePresentationDefinition
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.extractClientIdScheme
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

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
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "${REQUEST_URI.value} data is not valid"
                )
            val requestUriMethod =
                getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value) ?: "get"
            val httpMethod = determineHttpMethod(requestUriMethod)

            var body: Map<String, String>? = null
            var headers: Map<String, String>? = null


            if (httpMethod == HttpMethod.POST) {
                walletMetadata?.let { walletMetadata ->
                    isClientIdSchemeSupported(walletMetadata)
                    val processedWalletMetadata = process(walletMetadata)
                    body = mapOf(
                        "wallet_metadata" to URLEncoder.encode(
                            jacksonObjectMapper()
                                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                                .writeValueAsString(processedWalletMetadata),
                            StandardCharsets.UTF_8.toString()
                        )
                    )
                    headers = mapOf(
                        "content-type" to "application/x-www-form-urlencoded",
                        "accept" to "application/oauth-authz-req+jwt"
                    )
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

    fun setResponseUrl() {
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value)
            ?: throw Logger.handleException(
                exceptionType = "MissingInput",
                className = className,
                fieldPath = listOf(RESPONSE_MODE.value)
            )
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
        parseAndValidateClientMetadata(authorizationRequestParameters, walletMetadata, shouldValidateWithWalletMetadata)
        parseAndValidatePresentationDefinition(authorizationRequestParameters, walletMetadata, shouldValidateWithWalletMetadata)
    }

    private fun isClientIdSchemeSupported(walletMetadata: WalletMetadata) {
        val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
        val clientIdScheme = extractClientIdScheme(clientId)
        if (!walletMetadata.clientIdSchemesSupported.contains(clientIdScheme))
            throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "client_id_scheme is not support by wallet"
            )

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
            clientMetadata = authorizationRequestParameters[CLIENT_METADATA.value] as? ClientMetadata
        )
    }

}
