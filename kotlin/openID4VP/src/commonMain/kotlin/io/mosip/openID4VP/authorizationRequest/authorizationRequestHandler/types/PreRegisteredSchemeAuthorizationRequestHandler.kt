package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateAuthorizationRequestObjectAndParameters
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.extractClientIdentifier
import io.mosip.openID4VP.constants.ContentType.APPLICATION_JSON
import okhttp3.Headers
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = PreRegisteredSchemeAuthorizationRequestHandler::class.simpleName!!

class PreRegisteredSchemeAuthorizationRequestHandler(
    private val trustedVerifiers: List<Verifier>,
    authorizationRequestParameters: MutableMap<String, Any>,
    walletMetadata: WalletMetadata?,
    private val shouldValidateClient: Boolean,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters, walletMetadata, setResponseUri) {
    override fun validateClientId() {
        if (!shouldValidateClient) return

        val clientId =  getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
        if (trustedVerifiers.none { it.clientId == clientId }) {
            throw  OpenID4VPExceptions.InvalidVerifier("Verifier is not trusted by the wallet", className)
        }
    }

    override fun validateRequestUriResponse(
        requestUriResponse: Map<String, Any>
    ) {

        authorizationRequestParameters = if (requestUriResponse.isEmpty())
            authorizationRequestParameters
        else {
            val headers = requestUriResponse["header"] as Headers
            val responseBody = requestUriResponse["body"].toString()

            if (isValidContentType(headers)) {
                val authorizationRequestObject = convertJsonToMap(responseBody)
                validateAuthorizationRequestObjectAndParameters(
                    authorizationRequestParameters,
                    authorizationRequestObject
                )
                authorizationRequestObject
            } else {
                throw OpenID4VPExceptions.InvalidData("Authorization Request must not be signed for given client_id_scheme", className)
            }
        }
    }

    override fun process(walletMetadata: WalletMetadata): WalletMetadata {
        val updatedWalletMetadata = walletMetadata.copy()
        updatedWalletMetadata.requestObjectSigningAlgValuesSupported = null
        return updatedWalletMetadata
    }

    override fun getHeadersForAuthorizationRequestUri(): Map<String, String> {
        return mapOf(
            "content-type" to APPLICATION_FORM_URL_ENCODED.value,
            "accept" to APPLICATION_JSON.value
        )
    }

    override fun validateAndParseRequestFields() {
        super.validateAndParseRequestFields()

        if (!shouldValidateClient) return

        val clientId =  getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
        val responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value)!!

        if (trustedVerifiers.none { it.clientId == clientId && it.responseUris.contains(responseUri) }) {
            throw OpenID4VPExceptions.InvalidVerifier("Verifier is not trusted by the wallet", className)
        }

    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains(APPLICATION_JSON.value, ignoreCase = true) == true
}