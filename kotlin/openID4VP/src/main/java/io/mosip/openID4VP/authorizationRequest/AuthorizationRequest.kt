package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Logger
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

private val logTag = Logger.getLogTag(AuthorizationRequest::class.simpleName!!)

data class AuthorizationRequest(
    val clientId: String,
    val responseType: String,
    val responseMode: String,
    var presentationDefinition: Any,
    val responseUri: String,
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
            encodedAuthorizationRequest: String, setResponseUri: (String) -> Unit
        ): AuthorizationRequest {
            try {
                val queryStart = encodedAuthorizationRequest.indexOf('?') + 1
                val encodedString = encodedAuthorizationRequest.substring(queryStart)
                val decodedString =
                    Decoder.decodeBase64ToString(encodedString)
                val decodedAuthorizationRequest =
                    encodedAuthorizationRequest.substring(0, queryStart) + decodedString
                return parseAuthorizationRequest(decodedAuthorizationRequest, setResponseUri)
            } catch (e: Exception) {
                throw e
            }
        }

        private fun parseAuthorizationRequest(
            decodedAuthorizationRequest: String, setResponseUri: (String) -> Unit
        ): AuthorizationRequest {
            try {
                val queryStart = decodedAuthorizationRequest.indexOf('?') + 1
                val queryString = decodedAuthorizationRequest.substring(queryStart)
                val encodedQuery = URLEncoder.encode(queryString, StandardCharsets.UTF_8.toString())
                val uriString = "?$encodedQuery"
                val uri = URI(uriString)
                val query = uri.query
                    ?: throw AuthorizationRequestExceptions.InvalidQueryParams("Query parameters are missing in the Authorization request")

                val params = extractQueryParams(query)
                validateQueryParams(params, setResponseUri)
                return createAuthorizationRequest(params)
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        private fun extractQueryParams(query: String): Map<String, String> {
            try {
                return query.split("&").map { it.split("=") }.associateBy({ it[0] }, {
                    if (it.size > 1) URLDecoder.decode(
                        it[1], StandardCharsets.UTF_8.toString()
                    ) else ""
                })
            } catch (exception: Exception) {
                throw AuthorizationRequestExceptions.InvalidQueryParams("Exception occurred when extracting the query params from Authorization Request : ${exception.message}")
            }
        }

        private fun validateQueryParams(
            params: Map<String, String>, setResponseUri: (String) -> Unit
        ) {
            //Keep response_uri as first param in this list because if any other required param is not present then we need this response_uri to send error to the verifier
            val requiredRequestParams = mutableListOf(
                "response_uri",
                "presentation_definition",
                "client_id",
                "response_type",
                "response_mode",
                "nonce",
                "state",
            )
            requiredRequestParams.forEach { param ->
                val value = params[param] ?: throw AuthorizationRequestExceptions.MissingInput(param)
                if (param == "response_uri") {
                    setResponseUri(value)
                }
                require(value.isNotEmpty()) {
                    throw AuthorizationRequestExceptions.InvalidInput(param)
                }
            }

            val optionalRequestParams = mutableListOf("client_metadata")
            optionalRequestParams.forEach { param ->
                params[param]?.let { value ->
                    require(value.isNotEmpty()) {
                        throw AuthorizationRequestExceptions.InvalidInput(param)
                    }
                }
            }
        }

        private fun createAuthorizationRequest(params: Map<String, String>): AuthorizationRequest {
            return AuthorizationRequest(
                clientId = params["client_id"]!!,
                responseType = params["response_type"]!!,
                responseMode = params["response_mode"]!!,
                presentationDefinition = params["presentation_definition"]!!,
                responseUri = params["response_uri"]!!,
                nonce = params["nonce"]!!,
                state = params["state"]!!,
                clientMetadata = params["client_metadata"],
            )
        }
    }
}