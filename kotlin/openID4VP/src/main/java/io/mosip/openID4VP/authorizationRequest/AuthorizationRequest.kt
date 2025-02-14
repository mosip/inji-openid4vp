package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.proofJwt.ProofJwtManager
import io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler.DidUtils.JwtPart.PAYLOAD
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.decodeBase64ToJSON
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.extractDataJsonFromJwt
import io.mosip.openID4VP.common.isJWT
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.dto.WalletMetadata
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import kotlinx.serialization.json.Json
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

private val className = AuthorizationRequest::class.simpleName!!
private val logTag = Logger.getLogTag(className)

enum class ClientIdScheme(val value: String) {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    DID("did")
}

data class AuthorizationRequest(
    val clientId: String,
    val clientIdScheme: String,
    val responseType: String,
    val responseMode: String?,
    var presentationDefinition: Any,
    val responseUri: String?,
    val redirectUri: String?,
    val nonce: String,
    val state: String,
    var clientMetadata: Any? = null
) {


    init {
        require(presentationDefinition is PresentationDefinition || presentationDefinition is String) {
            "presentationDefinition must be of type String or PresentationDefinition"
        }

        clientMetadata?.let {
            require(clientMetadata is ClientMetadata || clientMetadata is String) {
                "clientMetadata must be of type String or ClientMetadata"
            }
        }
    }

    companion object {
        fun validateAndGetAuthorizationRequest(
            encodedAuthorizationRequest: String,
            setResponseUri: (String) -> Unit,
            trustedVerifiers: List<Verifier>,
            shouldValidateClient: Boolean,
            walletMetadata: String?
        ): AuthorizationRequest {
            try {
                val queryStart = encodedAuthorizationRequest.indexOf('?') + 1
                val encodedString = encodedAuthorizationRequest.substring(queryStart)
                val decodedQueryString = Decoder.decodeBase64ToString(encodedString)
                val authorizationRequestParams = parseAuthorizationRequest(decodedQueryString, walletMetadata)
                validateVerifier(trustedVerifiers, authorizationRequestParams, shouldValidateClient)
                validateAuthorizationRequestParams(authorizationRequestParams, setResponseUri)
                return createAuthorizationRequest(authorizationRequestParams)
            } catch (e: Exception) {
                throw e
            }
        }

        private fun parseAuthorizationRequest(
            queryString: String,
            walletMetadata: String?
        ): MutableMap<String, Any> {
            try {
                val encodedQuery = URLEncoder.encode(queryString, StandardCharsets.UTF_8.toString())
                val uriString = "?$encodedQuery"
                val uri = URI(uriString)
                val query = uri.query
                    ?: throw Logger.handleException(
                        exceptionType = "InvalidQueryParams",
                        message = "Query parameters are missing in the Authorization request",
                        className = className
                    )
                val params = extractQueryParams(query)
                return fetchAuthorizationRequestMap(params, walletMetadata)
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        private fun fetchAuthorizationRequestMap(
            params: MutableMap<String, Any>,
            walletMetadata: String?
        ): MutableMap<String, Any> {
            var authorizationRequestMap =  getValue(params,"request_uri")?.let { requestUri ->
                 fetchAuthRequestObjectByReference(params, requestUri, walletMetadata)
            } ?: params

            authorizationRequestMap = parseAndValidateClientMetadataInAuthorizationRequest(authorizationRequestMap)
            authorizationRequestMap = parseAndValidatePresentationDefinitionInAuthorizationRequest(authorizationRequestMap)
            return authorizationRequestMap
        }

        private fun fetchAuthRequestObjectByReference(
            params: MutableMap<String, Any>,
            requestUri: String,
            walletMetadata: String?
        ): MutableMap<String, Any> {
            try {
                val requestUriMethod = getValue(params, "request_uri_method") ?: "get"
                validateRootFieldInvalidScenario("request_uri", requestUri)
                validateRootFieldInvalidScenario("request_uri_method", requestUriMethod)
                val httpMethod = determineHttpMethod(requestUriMethod)
                var headers : Map<String, String>? = null
                var body : Map<String, String>? = null

                if (httpMethod == HTTP_METHOD.POST) {
                    walletMetadata?.let {
                        Json.decodeFromString<WalletMetadata>(walletMetadata)

                        body = mapOf(
                            "wallet_metadata" to URLEncoder.encode(
                                walletMetadata,
                                StandardCharsets.UTF_8.toString()
                            )
                        )
                        headers = mapOf(
                            "content-type" to "application/x-www-form-urlencoded",
                            "accept" to "application/oauth-authz-req+jwt"
                        )
                    }
                }

                val response = sendHTTPRequest(requestUri, httpMethod, body, headers)
                val authorizationRequestObject = extractAuthorizationRequestData(response, params)
                return authorizationRequestObject
            } catch (exception: Exception) {
                println("Exception is $exception")
                throw exception
            }
        }

        private fun extractAuthorizationRequestData(
            response: String,
            params: MutableMap<String, Any>
        ): MutableMap<String, Any> {
            val authorizationRequestObject: MutableMap<String, Any>
            if (isJWT(response)) {
                authorizationRequestObject = extractDataJsonFromJwt(response, PAYLOAD)
                validateMatchOfAuthRequestObjectAndParams(params, authorizationRequestObject)
                val proof = ProofJwtManager()
                proof.verifyJWT(
                    response,
                    getValue(authorizationRequestObject,"client_id")!!,
                    getValue(authorizationRequestObject,"client_id_scheme")!!,
                )
            } else {
                authorizationRequestObject = decodeBase64ToJSON(response)
                validateMatchOfAuthRequestObjectAndParams(params, authorizationRequestObject)
            }
            return authorizationRequestObject
        }

        private fun createAuthorizationRequest(
            params: Map<String, Any>
        ): AuthorizationRequest {
            return AuthorizationRequest(
                clientId = getValue(params, "client_id")!!,
                clientIdScheme = getValue(params, "client_id_scheme")!!,
                responseType = getValue(params, "response_type")!!,
                responseMode = getValue(params, "response_mode"),
                presentationDefinition = params["presentation_definition"]!!,
                responseUri = getValue(params,"response_uri"),
                redirectUri = getValue(params,"redirect_uri"),
                nonce = getValue(params,"nonce")!!,
                state = getValue(params, "state")!!,
                clientMetadata = getValue(params, "client_metadata"),
            )
        }

    }
}