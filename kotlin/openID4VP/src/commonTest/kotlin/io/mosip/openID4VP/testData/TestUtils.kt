package io.mosip.openID4VP.testData

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID_SCHEME
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.JWSUtil.Companion.createJWS
import kotlinx.serialization.json.JsonObject
import java.lang.reflect.Field
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import kotlin.test.assertEquals

fun setField(instance: Any, fieldName: String, value: Any?) {
    val field: Field = instance::class.java.getDeclaredField(fieldName)
    field.isAccessible = true
    field.set(instance, value)
}

fun createUrlEncodedData(
    requestParams: Map<String, String?>,
    verifierSentAuthRequestByReference: Boolean? = false,
    clientIdScheme: ClientIdScheme,
    applicableFields: List<String>? = null,
    draftVersion: Int = 23,
): String {
    val paramList = when (verifierSentAuthRequestByReference) {
        true -> {
            if (draftVersion == 23)
                authRequestParamsByReferenceDraft23
            else
                authRequestParamsByReferenceDraft21
        }

        else -> applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    }
    val authorizationRequestParam =
        createAuthorizationRequest(paramList, requestParams, draftVersion) as Map<String, Any>

    val charset = StandardCharsets.UTF_8.toString()

    val queryString = authorizationRequestParam.entries.joinToString("&") {
        "${it.key}=${URLEncoder.encode(it.value?.toString() ?: "", charset)}"
    }
//    val urlEncodedQueryParameters = URLEncoder.encode(queryString, charset)
    return "openid4vp://authorize?$queryString"

}

fun createAuthorizationRequestObject(
    clientIdScheme: ClientIdScheme,
    authorizationRequestParams: Map<String, String>,
    applicableFields: List<String>? = null,
    addValidSignature: Boolean? = true,
    jwtHeader: JsonObject? = null,
    isPresentationDefinitionUriPresent: Boolean? = false,
    draftVersion: Int = 23,
    removeClientId: Boolean = false,
): Any {
    val paramList =
        applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    return createAuthorizationRequest(
        paramList,
        authorizationRequestParams,
        draftVersion
    ).let { authRequestParam ->

        val param = if (isPresentationDefinitionUriPresent != true) {
            authRequestParam + clientMetadataPresentationDefinitionMap
        } else {
            if (clientIdScheme != ClientIdScheme.PRE_REGISTERED) {
                authRequestParam + mapOf(
                    CLIENT_METADATA.value to clientMetadataMap
                )
            } else {
                authRequestParam
            }
        }.toMutableMap()

        if (removeClientId) {
            param.remove(CLIENT_ID.value)
        }

        createJWS(param, addValidSignature!!, jwtHeader)

    }
}

private fun createAuthorizationRequest(
    paramList: List<String>,
    requestParams: Map<String, String?>,
    draftVersion: Int = 23,
): MutableMap<String, String?> {
    var params: List<String> = paramList
    if (draftVersion == 21) {
        params = paramList + listOf(CLIENT_ID_SCHEME.value)
    }
    val authorizationRequestParam = params
        .filter { requestParams.containsKey(it) }
        .associateWith { requestParams[it] }
        .toMutableMap()
    return authorizationRequestParam
}

fun assertOpenId4VPException(exception: OpenID4VPExceptions, expectedMessage: String, expectedErrorCode: String, expectedVerifierResponse: NetworkResponse? = null) {
    assertEquals(expectedMessage, exception.message)
    assertEquals(expectedErrorCode, exception.errorCode)
    if(expectedVerifierResponse != null){
        assertEquals(expectedVerifierResponse.toString(), exception.networkResponse.toString())
    }
}