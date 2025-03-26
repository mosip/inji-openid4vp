package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.toJsonEncodedMap
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.constants.HttpMethod

private val className = DirectPostResponseModeHandler::class.simpleName!!


class DirectPostResponseModeHandler: ResponseModeBasedHandler() {
    override fun validate(
        clientMetadata: ClientMetadata?,
        walletMetadata: WalletMetadata?,
        shouldValidateWithWalletMetadata: Boolean
    ) {
        return
    }

    override fun sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        url: String,
        authorizationResponse: AuthorizationResponse
    ): String {
        val bodyParams: Map<String, String> = authorizationResponse.toJsonEncodedMap()
        val response = sendHTTPRequest(
            url = url,
            method = HttpMethod.POST,
            bodyParams = bodyParams,
            headers = mapOf("Content-Type" to APPLICATION_FORM_URL_ENCODED.value)
        )
        return response["body"].toString()
    }
}