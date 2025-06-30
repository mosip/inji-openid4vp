package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.*
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

private val className = AuthorizationRequest::class.simpleName!!

fun getAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    trustedVerifiers: List<Verifier>,
    walletMetadata: WalletMetadata?,
    setResponseUri: (String) -> Unit,
    shouldValidateClient: Boolean
): ClientIdSchemeBasedAuthorizationRequestHandler {
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)
    validate(CLIENT_ID.value, clientId, className)
    val clientIdScheme = extractClientIdScheme(authorizationRequestParameters)
    return when (clientIdScheme) {
        PRE_REGISTERED.value -> PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            shouldValidateClient,
            setResponseUri
        )
        ClientIdScheme.REDIRECT_URI.value -> RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri
        )
        ClientIdScheme.DID.value -> DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri
        )
        else -> throw OpenID4VPExceptions.InvalidData("Given client_id_scheme is not supported", className)
    }
}

fun extractQueryParameters(query: String): MutableMap<String, Any> {
    try {
        val urlDecodedQueryString = URLDecoder.decode(query, StandardCharsets.UTF_8.toString())
        return urlDecodedQueryString.split("&").map { it.split("=") }
            .associateByTo(mutableMapOf(), { it[0] }, { it[1] })
    } catch (exception: Exception) {
        throw  OpenID4VPExceptions.InvalidQueryParams("Exception occurred when extracting the query params from Authorization Request : ${exception.message}", className)
    }
}

fun validateAuthorizationRequestObjectAndParameters(
    params: Map<String, Any>,
    authorizationRequestObject: Map<String, Any>,
) {
    if (params[CLIENT_ID.value] != authorizationRequestObject[CLIENT_ID.value]) {
        throw  OpenID4VPExceptions.InvalidData("Client Id mismatch in Authorization Request parameter and the Request Object",
            className)
    }
    if(params.containsKey(CLIENT_ID_SCHEME.value) && params[CLIENT_ID_SCHEME.value] != authorizationRequestObject[CLIENT_ID_SCHEME.value]) {
        throw  OpenID4VPExceptions.InvalidData("Client Id Scheme mismatch in Authorization Request parameter and the Request Object", className)
    }
}

fun extractClientIdScheme(authorizationRequestParameters: Map<String, Any>): String {
    if(authorizationRequestParameters.containsKey(CLIENT_ID_SCHEME.value)) {
        return getStringValue(authorizationRequestParameters, CLIENT_ID_SCHEME.value)!!
    }
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    val components = clientId.split(":", limit = 2)

    return if (components.size > 1) {
        components[0]
    } else {
        // Fallback client_id_scheme pre-registered; pre-registered clients MUST NOT contain a : character in their Client Identifier
        PRE_REGISTERED.value
    }
}


fun extractClientIdentifier(authorizationRequestParameters: Map<String, Any>): String {
    if(authorizationRequestParameters.containsKey(CLIENT_ID_SCHEME.value)) {
        return  getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    }
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    val components = clientId.split(":", limit = 2)
    return if (components.size > 1) {
        val clientIdScheme = components[0]
        // DID client ID scheme will have the client id itself with did prefix, example - did:example:123#1. So there will not be additional prefix stating client_id_scheme
        if (clientIdScheme == ClientIdScheme.DID.value) {
            clientId
        } else {
            components[1]
        }
    } else {
        // client_id_scheme is optional (Fallback client_id_scheme - pre-registered) i.e., a : character is not present in the Client Identifier
        clientId
    }
}
