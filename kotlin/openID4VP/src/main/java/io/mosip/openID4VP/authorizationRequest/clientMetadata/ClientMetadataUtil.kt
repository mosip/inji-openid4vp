package io.mosip.openID4VP.authorizationRequest.clientMetadata

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory

private val className = ClientMetadata::class.simpleName!!
fun parseAndValidateClientMetadata(
    authorizationRequestParameters: MutableMap<String, Any>,
    shouldValidateWithWalletMetadata: Boolean,
    walletMetadata: WalletMetadata?
) {
    val clientMetadata = authorizationRequestParameters[CLIENT_METADATA.value]?.let {
        when (it) {
            is String -> deserializeAndValidate(it, ClientMetadataSerializer)
            is Map<*, *> -> deserializeAndValidate(
                it as Map<String, Any>,
                ClientMetadataSerializer
            )

            else -> throw OpenID4VPExceptions.InvalidData("client_metadata must be of type String or Map", className)
        }
    }
    val responseMode = getStringValue(
        authorizationRequestParameters,
        RESPONSE_MODE.value
    )!!
    ResponseModeBasedHandlerFactory.get(responseMode)
        .validate(clientMetadata, walletMetadata, shouldValidateWithWalletMetadata)

    clientMetadata?.let {
        authorizationRequestParameters[CLIENT_METADATA.value] = it
    }
}