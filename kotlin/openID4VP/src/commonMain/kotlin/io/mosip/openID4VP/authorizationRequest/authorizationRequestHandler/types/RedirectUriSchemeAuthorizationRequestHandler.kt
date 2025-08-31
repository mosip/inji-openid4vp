package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.extractClientIdentifier
import io.mosip.openID4VP.authorizationRequest.validateAuthorizationRequestObjectAndParameters
import io.mosip.openID4VP.authorizationRequest.validateWalletNonce
import io.mosip.openID4VP.constants.ContentType.APPLICATION_JSON
import io.mosip.openID4VP.constants.ResponseMode.*
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import okhttp3.Headers
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.security.PublicKey

private val className = RedirectUriSchemeAuthorizationRequestHandler::class.simpleName!!

class RedirectUriSchemeAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    walletMetadata: WalletMetadata?,
    setResponseUri: (String) -> Unit,
    walletNonce: String
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters,walletMetadata, setResponseUri, walletNonce) {
    override fun isRequestUriSupported(): Boolean {
        return false
    }

    override fun isRequestObjectSupported(): Boolean {
        return true
    }

    override fun extractPublicKey(algorithm: RequestSigningAlgorithm, kid: String?): PublicKey {
        throw UnsupportedOperationException("Public key extraction is not supported for Redirect URI scheme")
    }

    override fun process(walletMetadata: WalletMetadata): WalletMetadata {
        val updatedWalletMetadata = walletMetadata
        updatedWalletMetadata.requestObjectSigningAlgValuesSupported = null
        return updatedWalletMetadata
    }

    override fun getHeadersForAuthorizationRequestUri(): Map<String, String> {
        return mapOf(
            "content-type" to APPLICATION_FORM_URL_ENCODED.value,
            "accept" to APPLICATION_JSON.value
        )
    }

    override fun validateAndParseRequestFields(){
        super.validateAndParseRequestFields()
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value) ?:
        throw OpenID4VPExceptions.MissingInput(listOf(RESPONSE_MODE.value),"", className)
         when (responseMode) {
            DIRECT_POST.value, DIRECT_POST_JWT.value -> {
                validateUriCombinations(
                    authorizationRequestParameters,
                    RESPONSE_URI.value,
                    REDIRECT_URI.value
                )
            }
            else -> throw OpenID4VPExceptions.InvalidData("Given response_mode is not supported", className)
        }
    }

    private fun validateUriCombinations(
        authRequestParam: Map<String, Any>,
        validAttribute: String,
        inValidAttribute: String,
    )  {
        when {
            authRequestParam.containsKey(inValidAttribute) -> {
                throw OpenID4VPExceptions.InvalidData("$inValidAttribute should not be present for given response_mode", className)
            }
            else -> {
                val data = getStringValue(authRequestParam, validAttribute)
                validate(validAttribute,data, className)
            }
        }
        if(authRequestParam[validAttribute] != extractClientIdentifier(authRequestParam))
            throw OpenID4VPExceptions.InvalidData("$validAttribute should be equal to client_id for given client_id_scheme", className)

    }

}