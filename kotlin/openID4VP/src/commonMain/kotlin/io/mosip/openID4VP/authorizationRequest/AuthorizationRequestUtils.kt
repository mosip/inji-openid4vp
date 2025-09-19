package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.*
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.net.URI
import java.net.URLDecoder

private val className = AuthorizationRequest::class.simpleName!!

fun getAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    trustedVerifiers: List<Verifier>,
    walletMetadata: WalletMetadata?,
    setResponseUri: (String) -> Unit,
    shouldValidateClient: Boolean,
    walletNonce: String
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
            setResponseUri,
            walletNonce
        )
        ClientIdScheme.REDIRECT_URI.value -> RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )
        ClientIdScheme.DID.value -> DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )
        else -> throw OpenID4VPExceptions.InvalidData("Given client_id_scheme is not supported", className)
    }
}

fun extractQueryParameters(query: String): Map<String, Any> {
    try {
        val uri = URI(query)
        val queryParams: Map<String, String> = uri.rawQuery?.split("&")?.associate {
            val (key, value) = it.split("=")
            key to URLDecoder.decode(value, "UTF-8")
        } ?: throw OpenID4VPExceptions.InvalidQueryParams("Exception occurred when extracting the query params from Authorization Request : No Query params in the URI", className)

        return queryParams
    } catch (exception: Exception) {
        throw OpenID4VPExceptions.InvalidQueryParams("Exception occurred when extracting the query params from Authorization Request : ${exception.message}", className)
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

fun validateWalletNonce(requestUriResponse: Map<String, Any>, walletNonce: String) {
    if (requestUriResponse[WALLET_NONCE.value] != walletNonce) {
        throw OpenID4VPExceptions.InvalidData("wallet_nonce provided in the authorization request is not the same as shared by wallet", className)
    }
}

fun validateResponseTypeSupported(responseType: String) {
    ResponseType.entries.find { it.value == responseType } ?: throw OpenID4VPExceptions.InvalidData(
        "Response type $responseType is not supported",
        className
    )
}
