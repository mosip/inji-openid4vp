package io.mosip.openID4VP.testData

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID_SCHEME
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.testData.JWSUtil.Companion.createJWS
import kotlinx.serialization.json.JsonObject
import java.lang.reflect.Field
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

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
    draftVersion: Int = 23
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
        createAuthorizationRequest(paramList, requestParams) as Map<String, Any>

    val charset = StandardCharsets.UTF_8.toString()

    val queryString = authorizationRequestParam.entries.joinToString("&") {
        "${it.key}=${it.value}"
    }
    val urlEncodedQueryParameters = URLEncoder.encode(queryString, charset)
    return "openid4vp://authorize?$urlEncodedQueryParameters"

}

fun createAuthorizationRequestObject(
    clientIdScheme: ClientIdScheme,
    authorizationRequestParams: Map<String, String>,
    applicableFields: List<String>? = null,
    addValidSignature: Boolean? = true,
    jwtHeader: JsonObject? = null,
    isPresentationDefinitionUriPresent: Boolean? = false,
    draftVersion: Int = 23,
): Any {
    val mapper = jacksonObjectMapper()
    var paramList = applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    if(draftVersion == 21) {
        paramList = paramList + listOf(CLIENT_ID_SCHEME.value)
    }
    return createAuthorizationRequest(paramList, authorizationRequestParams).let { authRequestParam ->

        val param = if(isPresentationDefinitionUriPresent != true)
            authRequestParam + clientMetadataPresentationDefinitionMap
        else
            authRequestParam + mapOf(
                CLIENT_METADATA.value to clientMetadataMap
            )
        when (clientIdScheme) {
            ClientIdScheme.DID -> createJWS(param, addValidSignature!!, jwtHeader)
            else -> mapper.writeValueAsString(param)
        }
    }
}

private fun createAuthorizationRequest(
    paramList: List<String>,
    requestParams: Map<String, String?>
): MutableMap<String, String?> {
    val authorizationRequestParam = paramList
        .filter { requestParams.containsKey(it) }
        .associateWith { requestParams[it] }
        .toMutableMap()
    return authorizationRequestParam
}