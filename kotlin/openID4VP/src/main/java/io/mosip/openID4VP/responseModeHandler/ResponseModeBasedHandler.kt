package io.mosip.openID4VP.responseModeHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.common.validate

private val className = ResponseModeBasedHandler::class.simpleName!!

abstract class ResponseModeBasedHandler {

    open fun validate(
        clientMetadata: ClientMetadata?,
        walletMetadata: WalletMetadata?,
        shouldValidateWithWalletMetadata: Boolean
    ){
        return
    }

    abstract fun sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        url: String,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
    ): String

    fun setResponseUrl(
        authorizationRequestParameters: Map<String, Any>,
        setResponseUri: (String) -> Unit
    ) {
        val responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value)
        validate(RESPONSE_URI.value, responseUri, className)
        if (!isValidUrl(responseUri!!)) {
            throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "invalid_request: ${RESPONSE_URI.value} data is not valid"
            )
        }
        setResponseUri(responseUri)
    }
}