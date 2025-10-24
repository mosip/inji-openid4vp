package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID_SCHEME
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.NONCE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REDIRECT_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI_METHOD
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_TYPE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.STATE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.TRANSACTION_DATA
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
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import java.security.PublicKey

private val className = ClientIdSchemeBasedAuthorizationRequestHandler::class.simpleName!!

abstract class ClientIdSchemeBasedAuthorizationRequestHandler(
    var authorizationRequestParameters: MutableMap<String, Any>,
    val walletMetadata: WalletMetadata?,
    private val setResponseUri: (String) -> Unit,
    val walletNonce: String,
) {
    private var shouldValidateWithWalletMetadata = false

    open fun validateClientId() {
        return
    }

    abstract fun isSignedRequestSupported(): Boolean

    abstract fun isUnsignedRequestSupported(): Boolean

    abstract fun clientIdScheme(): String

    fun fetchAuthorizationRequest() {

        val requestUri = getStringValue(authorizationRequestParameters, REQUEST_URI.value)
        val request = getStringValue(
            authorizationRequestParameters,
            REQUEST.value
        )

        if (request != null && requestUri != null) {
            throw OpenID4VPExceptions.InvalidData(
                "Both 'request' and 'request_uri' cannot be present in same authorization request",
                className
            )
        }

        if (request != null) {
            handleRequestObjectAsValue(request)
        } else if (requestUri != null) {
            handleRequestObjectByReference(requestUri)
        } else {
            handleUrlEncodedRequest()
        }
    }

    private fun handleRequestObjectByReference(requestUri: String) {
        val requestUriResponse: NetworkResponse
        if (!isSignedRequestSupported()) {
            throw OpenID4VPExceptions.InvalidData(
                "Signed request (via request_uri) is not supported for given client_id_scheme - ${this.clientIdScheme()}",
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
            body = mapOf("wallet_nonce" to walletNonce)
            walletMetadata?.let { walletMetadata ->
                isClientIdSchemeSupported(walletMetadata)
                val processedWalletMetadata = process(walletMetadata)
                body = body?.plus(
                    mapOf(
                        "wallet_metadata" to encodeToJsonString(
                            processedWalletMetadata,
                            "wallet_metadata",
                            className
                        )
                    )
                )
                headers = mapOf(
                    "content-type" to ContentType.APPLICATION_FORM_URL_ENCODED.value,
                    "accept" to ContentType.APPLICATION_JWT.value
                )
                shouldValidateWithWalletMetadata = true
            }
        }
        try {
            requestUriResponse = sendHTTPRequest(requestUri, httpMethod, body, headers)
            if (!requestUriResponse.isOk()) {
                throw OpenID4VPExceptions.InvalidData(
                    "Error while fetching request_uri: HTTP status code ${requestUriResponse.statusCode} & body: ${requestUriResponse.body}",
                    className,
                )
            }
            this.authorizationRequestParameters =
                this.validateRequestUriResponse(requestUriResponse, httpMethod)
        } catch (e: OpenID4VPExceptions) {
            throw e
        } catch (e: Exception) {
            throw OpenID4VPExceptions.GenericFailure(
                "Network error while fetching request_uri: ${e.message}",
                className,
            )
        }

    }

    private fun handleUrlEncodedRequest() {
        if (!isUnsignedRequestSupported()) {
            throw OpenID4VPExceptions.InvalidData(
                "unsigned request is not supported for given client_id_scheme - ${this.clientIdScheme()}",
                className
            )
        }
    }

    private fun handleRequestObjectAsValue(request: String) {
        validate(REQUEST.value,request, className, "jwt")
        if (!isSignedRequestSupported()) {
            throw OpenID4VPExceptions.InvalidData(
                "Signed request (via request) is not supported for given client_id_scheme - ${this.clientIdScheme()}",
                className
            )
        }

        validateJWTRequest(request)
        val authorizationRequestObject = try {
            JWSHandler.extractDataJsonFromJws(request, JWSHandler.JwsPart.PAYLOAD)
        } catch (e: Exception) {
            throw OpenID4VPExceptions.InvalidData(
                "Failed to parse payload from Authorization Request Object: ${e.message}",
                className
            )
        }

        validateAuthorizationRequestObjectAndParameters(this.authorizationRequestParameters, authorizationRequestObject, className)

        this.authorizationRequestParameters = authorizationRequestObject
    }


    private fun validateRequestUriResponse(
        requestUriResponse: NetworkResponse,
        httpMethod: HttpMethod
    ): MutableMap<String, Any> {
        val responseBody: String = requestUriResponse.body
        val headers = requestUriResponse.headers

        if (responseBody.isEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "Missing body in request_uri response",
                className
            )
        }

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

        validateJWTRequest(responseBody)

        val authorizationRequestObject = try {
            JWSHandler.extractDataJsonFromJws(responseBody, JWSHandler.JwsPart.PAYLOAD)
        } catch (e: Exception) {
            throw OpenID4VPExceptions.InvalidData(
                "Failed to parse payload from Authorization Request Object: ${e.message}",
                className
            )
        }

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

        validateAuthorizationRequestObjectAndParameters(
            authorizationRequestParameters,
            authorizationRequestObject,
            className
        )

        return authorizationRequestObject
    }


    private fun validateJWTRequest(jws: String) {
        try {
            val header = try {
                JWSHandler.extractDataJsonFromJws(jws, JWSHandler.JwsPart.HEADER)
            } catch (e: Exception) {
                throw OpenID4VPExceptions.VerificationFailure(
                    "JWS header extraction failed: ${e.message}",
                    className,
                )
            }

            val algString = header["alg"] as? String
                ?: throw OpenID4VPExceptions.InvalidData(
                    "'alg' is not present in JWS header",
                    className,
                    OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
                )

            validateAuthorizationRequestSigningAlgorithm(algString)

            val algorithm = RequestSigningAlgorithm.valueOf(algString)

            val kid = header["kid"] as? String

            val publicKey = extractPublicKey(algorithm = algorithm, kid = kid)

            try {
                JWSHandler.verify(jws, publicKey)
            } catch (e: Exception) {
                throw OpenID4VPExceptions.VerificationFailure(
                    "JWS signature verification failed: ${e.message}",
                    className
                )
            }
        } catch (e: OpenID4VPExceptions) {
            throw OpenID4VPExceptions.InvalidData(
                "Request URI response validation failed - ${e.message}",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        } catch (e: Exception) {
            throw OpenID4VPExceptions.VerificationFailure(
                "Request URI response validation failed ${e.message}",
                className
            )
        }
    }


    abstract fun extractPublicKey(algorithm: RequestSigningAlgorithm, kid: String?): PublicKey

    private fun isValidContentType(headers: Map<String, List<String>>): Boolean {
        val contentTypeValues: List<String> = headers.entries
            .firstOrNull { it.key.equals("content-type", ignoreCase = true) }
            ?.value ?: return false
        return contentTypeValues.any { value ->
            value.contains(ContentType.APPLICATION_JWT.value, ignoreCase = true)
        }
    }

    private fun validateAuthorizationRequestSigningAlgorithm(
        algorithm: String,
    ) {

        if (shouldValidateWithWalletMetadata) {
            walletMetadata?.let {
                if (!it.requestObjectSigningAlgValuesSupported!!.contains(
                        RequestSigningAlgorithm.fromValue(
                            algorithm
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


    /**
     * Sets the response URI for this authorization request based on the `response_mode` parameter.
     *
     * Reads `response_mode` from the authorization request parameters and invokes the appropriate
     * response-mode handler which will call the configured `setResponseUri` callback to set the URI.
     *
     * @throws OpenID4VPExceptions.MissingInput if the `response_mode` parameter is not present.
     */
    fun setResponseUrl() {
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value)
            ?: throw OpenID4VPExceptions.MissingInput(listOf(RESPONSE_MODE.value), "", className)
        ResponseModeBasedHandlerFactory.get(responseMode)
            .setResponseUrl(authorizationRequestParameters, setResponseUri)
    }

    /**
     * Validates and parses authorization request fields from the handler's parameter map.
     *
     * Performs an early rejection if `transaction_data` is present, validates required fields
     * (`response_type`, `nonce`) and optional `state`, parses and validates client metadata
     * according to whether wallet metadata validation is enabled, and parses the presentation
     * definition (taking wallet support for presentationDefinition URI into account).
     *
     * @throws OpenID4VPExceptions.InvalidTransactionData if the `transaction_data` field is present.
     */
    open fun validateAndParseRequestFields() {
        if (authorizationRequestParameters.containsKey(TRANSACTION_DATA.value)) {
            throw OpenID4VPExceptions.InvalidTransactionData(
                "Invalid Request: transaction_data is not supported in the authorization request",
                className
            )
        }
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
