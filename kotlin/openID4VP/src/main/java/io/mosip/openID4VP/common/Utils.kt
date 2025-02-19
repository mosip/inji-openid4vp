package io.mosip.openID4VP.common

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.jwt.JwtHandler
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

private const val URL_PATTERN = "^https://(?:[\\w-]+\\.)+[\\w-]+(?:/[\\w\\-.~!$&'()*+,;=:@%]+)*/?(?:\\?[^#\\s]*)?(?:#.*)?$"

fun isValidUrl(url : String): Boolean {
    return url.matches(URL_PATTERN.toRegex())
}

fun convertJsonToMap(jsonString: String): MutableMap<String, Any> {
    val mapper = jacksonObjectMapper()
    return mapper.readValue(
        jsonString,
        object : TypeReference<MutableMap<String, Any>>() {})
}

fun isJWT(authorizationRequest: String): Boolean {
    return authorizationRequest.split(".").size == 3
}

fun determineHttpMethod(method: String): HTTP_METHOD {
    return when (method.lowercase()) {
        "get" -> HTTP_METHOD.GET
        "post" -> HTTP_METHOD.POST
        else -> throw IllegalArgumentException("Unsupported HTTP method: $method")
    }
}

fun extractDataJsonFromJwt(jwtToken: String, part: JwtHandler.JwtPart): MutableMap<String, Any> {
    val components = jwtToken.split(".")
    val payload = components[part.number]
    val standardizedBase64 = makeBase64Standard(payload)
    return decodeBase64ToJSON(standardizedBase64)
}

fun makeBase64Standard(base64String: String): String {
    var base64 = base64String
        .replace("-", "+")
        .replace("_", "/")

    while (base64.length % 4 != 0) {
        base64 += "="
    }
    return base64
}

fun decodeBase64ToJSON(base64String: String): MutableMap<String, Any> {
    val decodedString = try {
        Decoder.decodeBase64ToString(base64String)
    } catch (e: IllegalArgumentException) {
        throw Exception("JWT payload decoding failed: ${e.message}")
    }
    return convertJsonToMap(decodedString)
}

fun getStringValue(params: Map<String, Any>, key: String): String? {
    return params[key]?.toString()
}

