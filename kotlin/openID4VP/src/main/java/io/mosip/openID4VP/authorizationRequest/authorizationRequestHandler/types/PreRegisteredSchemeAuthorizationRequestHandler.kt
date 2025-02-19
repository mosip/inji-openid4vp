package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.validateMatchOfAuthRequestObjectAndParams
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import okhttp3.Headers

private val className = PreRegisteredSchemeAuthorizationRequestHandler::class.simpleName!!

class PreRegisteredSchemeAuthorizationRequestHandler(
    private val trustedVerifiers: List<Verifier>,
    authorizationRequestParameters: MutableMap<String, Any>,
    private val shouldValidateClient: Boolean,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters, setResponseUri) {
    override fun validateClientId() {
        super.validateClientId()
        if (!shouldValidateClient) return
        when {
            trustedVerifiers.isEmpty() -> throw Logger.handleException(
                exceptionType = "EmptyVerifierList",
                className = className
            )

            trustedVerifiers.none {
                it.clientId == getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
            } -> throw Logger.handleException(
                exceptionType = "InvalidVerifier",
                className = className
            )
        }
    }

    override fun fetchAuthorizationRequest() {
        authorizationRequestParameters = getStringValue(authorizationRequestParameters, REQUEST_URI.value)?.let {
            if (!isValidUrl(it))
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "$REQUEST_URI data is not valid"
                )
            val requestUriMethod = getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value) ?: "get"
            val httpMethod = determineHttpMethod(requestUriMethod)
            val response = sendHTTPRequest(it, httpMethod)
            val headers = response["header"] as Headers
            val responseBody = response["body"].toString()

            if(isValidContentType(headers)) {
                val authorizationRequestObject = convertJsonToMap(responseBody)
                validateMatchOfAuthRequestObjectAndParams(authorizationRequestParameters, authorizationRequestObject)
                authorizationRequestObject
            }else {
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "Authorization Request must not be signed for given client_id_scheme"
                )
            }
        } ?: authorizationRequestParameters
    }

    override fun validateAndParseRequestFields() {
        super.validateAndParseRequestFields()

        if (!shouldValidateClient) return
        when {
            trustedVerifiers.isEmpty() -> throw Logger.handleException(
                exceptionType = "EmptyVerifierList",
                className = className
            )

            trustedVerifiers.none {
                it.clientId == getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
                        &&  it.responseUris.contains(getStringValue(authorizationRequestParameters, RESPONSE_URI.value)!!)
            } -> throw Logger.handleException(
                exceptionType = "InvalidVerifier",
                className = className
            )
        }

    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains("application/json", ignoreCase = true) == true
}