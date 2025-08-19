package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateAuthorizationRequestObjectAndParameters
import io.mosip.openID4VP.authorizationRequest.validateWalletNonce
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isJWS
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.HEADER
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.PAYLOAD
import io.mosip.openID4VP.constants.ContentType.APPLICATION_JWT
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.vercred.vcverifier.publicKey.types.did.DidPublicKeyResolver
import okhttp3.Headers

private val className = DidSchemeAuthorizationRequestHandler::class.simpleName!!

class DidSchemeAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    walletMetadata: WalletMetadata?,
    setResponseUri: (String) -> Unit,
    walletNonce: String
) : ClientIdSchemeBasedAuthorizationRequestHandler(
    authorizationRequestParameters,
    walletMetadata,
    setResponseUri,
    walletNonce
) {

    override fun validateRequestUriResponse(
        requestUriResponse: Map<String, Any>
    ) {
        if (requestUriResponse.isNotEmpty()) {
            val headers = requestUriResponse["header"] as Headers
            val responseBody = requestUriResponse["body"].toString()

            if (isValidContentType(headers) && isJWS(responseBody)) {
                val didUrl = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!

                val header = JWSHandler.extractDataJsonFromJws(responseBody, HEADER)
                validateAuthorizationRequestSigningAlgorithm(header)

                println("Validating JWS signature for didUrl: $didUrl, header: $header, jws: $responseBody")
                JWSHandler.verify(responseBody, DidPublicKeyResolver(), didUrl)

                val authorizationRequestObject =
                    JWSHandler.extractDataJsonFromJws(responseBody, PAYLOAD)

                validateAuthorizationRequestObjectAndParameters(
                    authorizationRequestParameters,
                    authorizationRequestObject
                )

                val httpMethod =
                    getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value)?.let {
                        determineHttpMethod(it)
                    } ?: HttpMethod.GET

                if (httpMethod == HttpMethod.POST)
                    validateWalletNonce(authorizationRequestObject, walletNonce)
                authorizationRequestParameters = authorizationRequestObject

            } else
                throw OpenID4VPExceptions.InvalidData(
                    "Authorization Request must be signed for given client_id_scheme",
                    className
                )
        } else throw OpenID4VPExceptions.MissingInput(listOf(REQUEST_URI.value), "", className)

    }

    override fun process(walletMetadata: WalletMetadata): WalletMetadata {
        if (walletMetadata.requestObjectSigningAlgValuesSupported.isNullOrEmpty())
            throw OpenID4VPExceptions.InvalidData(
                "request_object_signing_alg_values_supported is not present in wallet metadata",
                className
            )
        return walletMetadata
    }

    override fun getHeadersForAuthorizationRequestUri(): Map<String, String> {
        return mapOf(
            "content-type" to APPLICATION_FORM_URL_ENCODED.value,
            "accept" to APPLICATION_JWT.value
        )
    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains(APPLICATION_JWT.value, ignoreCase = true) == true

    private fun validateAuthorizationRequestSigningAlgorithm(headers: MutableMap<String, Any>) {
        if (shouldValidateWithWalletMetadata) {
            val alg = headers["alg"] as String
            walletMetadata?.let {
                if (!it.requestObjectSigningAlgValuesSupported!!.contains(
                        RequestSigningAlgorithm.fromValue(
                            alg
                        )
                    )
                )
                    throw OpenID4VPExceptions.InvalidData(
                        "request_object_signing_alg is not support by wallet",
                        className
                    )
            }
        }
    }
}

