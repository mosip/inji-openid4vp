package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.DidSchemeAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.PreRegisteredSchemeAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.RedirectUriSchemeAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

private val className = AuthorizationRequest::class.simpleName!!

fun getAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    trustedVerifiers: List<Verifier>,
    setResponseUri: (String) -> Unit,
    shouldValidateClient: Boolean
): ClientIdSchemeBasedAuthorizationRequestHandler {
    val clientIdScheme = getStringValue(authorizationRequestParameters, CLIENT_ID_SCHEME.value)
        ?: ClientIdScheme.PRE_REGISTERED.value
    authorizationRequestParameters[CLIENT_ID_SCHEME.value] = clientIdScheme
    return when (clientIdScheme) {
        ClientIdScheme.PRE_REGISTERED.value -> PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            shouldValidateClient,
            setResponseUri
        )

        ClientIdScheme.REDIRECT_URI.value -> RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            setResponseUri
        )

        ClientIdScheme.DID.value -> DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            setResponseUri
        )

        else -> throw Logger.handleException(
            exceptionType = "InvalidClientIdScheme",
            className = className,
            message = "Given client_id_scheme is not supported"
        )
    }
}

fun validateKey(
    authorizationRequestParameters: MutableMap<String, Any>,
    key: String,
) {
    val value = getStringValue(authorizationRequestParameters, key)
    if (value == null || value == "null" || value.isEmpty()) {
        throw Logger.handleException(
            exceptionType = if (authorizationRequestParameters[key] == null) "MissingInput" else "InvalidInput",
            fieldPath = listOf(key),
            className = AuthorizationRequest.toString(),
            fieldType = "String"
        )
    }
}

fun extractQueryParameters(query: String): MutableMap<String, Any> {
    try {
        val urlDecodedQueryString = URLDecoder.decode(query, StandardCharsets.UTF_8.toString())
        return urlDecodedQueryString.split("&").map { it.split("=") }
            .associateByTo(mutableMapOf(), { it[0] }, { it[1] })
    } catch (exception: Exception) {
        throw Logger.handleException(
            exceptionType = "InvalidQueryParams",
            message = "Exception occurred when extracting the query params from Authorization Request : ${exception.message}",
            className = className
        )
    }
}

fun parseAndValidatePresentationDefinitionInAuthorizationRequest(authorizationRequestParameters: MutableMap<String, Any>): MutableMap<String, Any> {
    val hasPresentationDefinition =
        authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION.value)
    val hasPresentationDefinitionUri =
        authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION_URI.value)
    var presentationDefinitionString = ""

    when {
        hasPresentationDefinition && hasPresentationDefinitionUri -> {
            throw Logger.handleException(
                exceptionType = "InvalidQueryParams",
                message = "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                className = className
            )
        }

        hasPresentationDefinition -> {
            validateKey(authorizationRequestParameters, PRESENTATION_DEFINITION.value)
            presentationDefinitionString =
                getStringValue(authorizationRequestParameters, PRESENTATION_DEFINITION.value)!!
        }

        hasPresentationDefinitionUri -> {
            try {
                validateKey(authorizationRequestParameters, PRESENTATION_DEFINITION_URI.value)
                val presentationDefinitionUri = getStringValue(
                    authorizationRequestParameters,
                    PRESENTATION_DEFINITION_URI.value
                )!!
                if (!isValidUrl(presentationDefinitionUri)) {
                    throw Logger.handleException(
                        exceptionType = "InvalidData",
                        className = className,
                        message = "$PRESENTATION_DEFINITION_URI data is not valid"
                    )
                }
                val response =
                    sendHTTPRequest(
                        url = presentationDefinitionUri,
                        method = HTTP_METHOD.GET
                    )
                presentationDefinitionString = response["body"].toString()
            } catch (exception: Exception) {
                throw exception
            }
        }

        else -> {
            throw Logger.handleException(
                exceptionType = "InvalidQueryParams",
                message = "Either presentation_definition or presentation_definition_uri request param must be present",
                className = className
            )
        }
    }

    val presentationDefinition =
        deserializeAndValidate((presentationDefinitionString), PresentationDefinitionSerializer)
    authorizationRequestParameters[PRESENTATION_DEFINITION.value] = presentationDefinition

    return authorizationRequestParameters
}

fun parseAndValidateClientMetadataInAuthorizationRequest(authorizationRequestParameters: MutableMap<String, Any>): MutableMap<String, Any> {
    var clientMetadata: ClientMetadata?
    getStringValue(authorizationRequestParameters, CLIENT_METADATA.value)?.let {
        clientMetadata =
            deserializeAndValidate(
                it,
                ClientMetadataSerializer
            )
        authorizationRequestParameters[CLIENT_METADATA.value] = clientMetadata!!
    }
    return authorizationRequestParameters
}

fun validateMatchOfAuthRequestObjectAndParams(
    params: MutableMap<String, Any>,
    authorizationRequestObject: MutableMap<String, Any>,
) {
    if (params[CLIENT_ID.value] != authorizationRequestObject[CLIENT_ID.value]) {
        throw Logger.handleException(
            exceptionType = "InvalidData",
            message = "Client Id mismatch in Authorization Request parameter and the Request Object",
            className = className
        )

    }
    if (params[CLIENT_ID_SCHEME.value] != null && params[CLIENT_ID_SCHEME.value] != authorizationRequestObject[CLIENT_ID_SCHEME.value]) {
        throw Logger.handleException(
            exceptionType = "InvalidData",
            message = "Client Id Scheme mismatch in Authorization Request parameter and the Request Object",
            className = className
        )
    }
}



