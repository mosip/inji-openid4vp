package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID_SCHEME
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.NONCE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REDIRECT_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI_METHOD
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_TYPE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.STATE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.WALLET_NONCE
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.parseAndValidateClientMetadata
import io.mosip.openID4VP.authorizationRequest.extractClientIdScheme
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.parseAndValidatePresentationDefinition
import io.mosip.openID4VP.authorizationRequest.validateAuthorizationRequestObjectAndParameters
import io.mosip.openID4VP.authorizationRequest.validateResponseTypeSupported
import io.mosip.openID4VP.authorizationRequest.validateWalletNonce
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isJWS
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import okhttp3.Headers
import java.security.PublicKey

private val className = ClientIdSchemeBasedAuthorizationRequestHandler::class.simpleName!!

abstract class ClientIdSchemeBasedAuthorizationRequestHandler(
    var authorizationRequestParameters: MutableMap<String, Any>,
    val walletMetadata: WalletMetadata?,
    private val setResponseUri: (String) -> Unit,
    val walletNonce: String,
) {
    protected var shouldValidateWithWalletMetadata = false

    open fun validateClientId() {
        return
    }

    abstract fun isRequestUriSupported(): Boolean

    abstract fun isRequestObjectSupported(): Boolean


    fun fetchAuthorizationRequest() {
        val requestUriResponse: Map<String, Any>

        val requestUri = getStringValue(authorizationRequestParameters, REQUEST_URI.value)

        if (requestUri != null) {
            if (!isRequestUriSupported()) {
                throw OpenID4VPExceptions.InvalidData(
                    "request_uri is not supported for given client_id_scheme",
                    className
                )
            }

            if (!isValidUrl(requestUri)) {
                throw OpenID4VPExceptions.InvalidData(
                    "${REQUEST_URI.value} data is not valid",
                    className
                )
            }

            val requestUriMethod =
                getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value) ?: "get"

            val httpMethod = try {
                determineHttpMethod(requestUriMethod)
            } catch (e: IllegalArgumentException) {
                throw OpenID4VPExceptions.InvalidData(
                    "Unsupported HTTP method: $requestUriMethod",
                    className,
                    OpenID4VPErrorCodes.INVALID_REQUEST_URI_METHOD
                )
            }

            var body: Map<String, String>? = null
            var headers: Map<String, String>? = null

            if (httpMethod == HttpMethod.POST) {
                walletMetadata?.let { walletMetadata ->
                    isClientIdSchemeSupported(walletMetadata)
                    val processedWalletMetadata = process(walletMetadata)
                    body = mapOf(
                        "wallet_metadata" to encodeToJsonString(
                            processedWalletMetadata,
                            "wallet_metadata",
                            className
                        )
                    )
                    headers = getHeadersForAuthorizationRequestUri()
                    shouldValidateWithWalletMetadata = true
                }
                body = body?.plus(mapOf("wallet_nonce" to walletNonce))
            }

            requestUriResponse = sendHTTPRequest(requestUri, httpMethod, body, headers)
            this.validateRequestUriResponse(requestUriResponse,walletNonce)
        } else {
            if (!isRequestObjectSupported()) {
                throw OpenID4VPExceptions.InvalidData(
                    "request object is not supported for given client_id_scheme",
                    className
                )
            }
        }
    }


    private fun validateRequestUriResponse(
        requestUriResponse: Map<String, Any>,
        walletNonce: String,
    ) {
        if (requestUriResponse.isEmpty()) {
            throw OpenID4VPExceptions.MissingInput(listOf(REQUEST_URI.value), "", className)
        }

        val headers = requestUriResponse["header"] as? Headers
            ?: throw OpenID4VPExceptions.InvalidData("Missing HTTP headers in request_uri response", className)

        val responseBody = requestUriResponse["body"]?.toString()
            ?: throw OpenID4VPExceptions.InvalidData("Missing body in request_uri response", className)

        if (!isValidContentType(headers)) {
            throw OpenID4VPExceptions.InvalidData(
                "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
                className
            )
        }

        if (!isJWS(responseBody)) {
            throw OpenID4VPExceptions.InvalidData(
                "Authorization Request Object must be a signed JWT",
                className
            )
        }

        val jwtHeader = try {
            JWSHandler.extractDataJsonFromJws(responseBody, JWSHandler.JwsPart.HEADER)
        } catch (e: Exception) {
            throw OpenID4VPExceptions.VerificationFailure(
                "Failed to parse JWS header: ${e.message}",
                className
            )
        }

        try {
            validateAuthorizationRequestSigningAlgorithm(jwtHeader)
            verifyJwt(responseBody)
        } catch (e: OpenID4VPExceptions) {
            throw e
        } catch (e: Exception) {
            throw OpenID4VPExceptions.VerificationFailure(
                "Request URI response validation failed ${e.message}",
                className
            )
        }

        val authorizationRequestObject = try {
            JWSHandler.extractDataJsonFromJws(responseBody, JWSHandler.JwsPart.PAYLOAD)
        } catch (e: Exception) {
            throw OpenID4VPExceptions.InvalidData(
                "Failed to parse payload from Authorization Request Object: ${e.message}",
                className
            )
        }

        try {
            validateAuthorizationRequestObjectAndParameters(
                authorizationRequestParameters,
                authorizationRequestObject
            )
        } catch (e: Exception) {
            throw OpenID4VPExceptions.InvalidData(
                "Authorization Request Object validation failed: ${e.message}",
                className
            )
        }

        val httpMethod = getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value)
            ?.let { determineHttpMethod(it) } ?: HttpMethod.GET

        if (httpMethod == HttpMethod.POST) {
            try {
                validateWalletNonce(authorizationRequestObject, walletNonce)
            } catch (e: Exception) {
                throw OpenID4VPExceptions.InvalidData(
                    "Wallet nonce validation failed: ${e.message}",
                    className
                )
            }
        }

        authorizationRequestParameters = authorizationRequestObject
    }


    private fun verifyJwt(jws: String) {
        val header = try {
            JWSHandler.extractDataJsonFromJws(jws, JWSHandler.JwsPart.HEADER)
        } catch (e: Exception) {
            throw OpenID4VPExceptions.VerificationFailure(
                "JWS header extraction failed: ${e.message}",
                className
            )
        }

        val algString = header["alg"] as? String
            ?: throw OpenID4VPExceptions.InvalidData(
                "Request URI response validation failed - 'alg' is missing in JWS header",
                className
            )

        val algorithm = RequestSigningAlgorithm.valueOf(algString)

        val kid = header["kid"] as? String

        val publicKey = try {
            extractPublicKey(algorithm = algorithm, kid = kid)
        } catch (e: Exception) {
            throw OpenID4VPExceptions.VerificationFailure(
                "Failed to extract public key: ${e.message}",
                className
            )
        }

        try {
            JWSHandler.verify(jws, publicKey)
        } catch (e: Exception) {
            throw OpenID4VPExceptions.VerificationFailure(
                "JWS signature verification failed: ${e.message}",
                className
            )
        }
    }



    abstract fun extractPublicKey(algorithm: RequestSigningAlgorithm, kid: String?): PublicKey

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains(
            ContentType.APPLICATION_JWT.value,
            ignoreCase = true
        ) == true

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
                        "request_object_signing_alg is not supported by wallet",
                        className
                    )
            }
        }
    }


    abstract fun process(walletMetadata: WalletMetadata): WalletMetadata

    abstract fun getHeadersForAuthorizationRequestUri(): Map<String, String>

    fun setResponseUrl() {
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value)
            ?: throw OpenID4VPExceptions.MissingInput(listOf(RESPONSE_MODE.value), "", className)
        ResponseModeBasedHandlerFactory.get(responseMode)
            .setResponseUrl(authorizationRequestParameters, setResponseUri)
    }

    open fun validateAndParseRequestFields() {
        val responseType = getStringValue(authorizationRequestParameters, RESPONSE_TYPE.value)
        validate(RESPONSE_TYPE.value, responseType, className)
        validateResponseTypeSupported(responseType!!)
        val nonce = getStringValue(authorizationRequestParameters, NONCE.value)
        validate(NONCE.value, nonce, className)
        val state = getStringValue(authorizationRequestParameters, STATE.value)
        state?.let {
            validate(STATE.value, state, className)
        }
        parseAndValidateClientMetadata(
            authorizationRequestParameters,
            shouldValidateWithWalletMetadata,
            walletMetadata
        )
        val presentationDefinitionUriSupported = !shouldValidateWithWalletMetadata ||
                walletMetadata?.presentationDefinitionURISupported ?: true
        parseAndValidatePresentationDefinition(
            authorizationRequestParameters,
            presentationDefinitionUriSupported
        )
    }


    private fun isClientIdSchemeSupported(walletMetadata: WalletMetadata) {
        val clientIdScheme = extractClientIdScheme(authorizationRequestParameters)
        if (!walletMetadata.clientIdSchemesSupported!!.contains(
                ClientIdScheme.fromValue(
                    clientIdScheme
                )
            )
        )
            throw OpenID4VPExceptions.InvalidData(
                "client_id_scheme is not support by wallet",
                className
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
            walletNonce = getStringValue(authorizationRequestParameters, WALLET_NONCE.value),
            state = getStringValue(authorizationRequestParameters, STATE.value),
            clientMetadata = authorizationRequestParameters[CLIENT_METADATA.value] as? ClientMetadata,
            clientIdScheme = getStringValue(authorizationRequestParameters, CLIENT_ID_SCHEME.value)
        )
    }


}
