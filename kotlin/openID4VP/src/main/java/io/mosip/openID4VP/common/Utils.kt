package io.mosip.openID4VP.common

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.constants.HttpMethod
import java.security.SecureRandom

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

fun isJWS(input: String): Boolean {
    return input.split(".").size == 3
}

fun determineHttpMethod(method: String): HttpMethod {
    return when (method.lowercase()) {
        "get" -> HttpMethod.GET
        "post" -> HttpMethod.POST
        else -> throw IllegalArgumentException("invalid_request_uri_method: Unsupported HTTP method: $method")
    }
}

fun getStringValue(params: Map<String, Any>, key: String): String? {
    return params[key]?.toString()
}

fun generateNonce(minEntropy: Int): String {
    val secureRandom = SecureRandom()
    val nonce = CharArray(minEntropy) {
        when (val randomChar = secureRandom.nextInt(62)) { // 26 (A-Z) + 26 (a-z) + 10 (0-9)
            in 0..25 -> 'A' + randomChar
            in 26..51 -> 'a' + (randomChar - 26)
            else -> '0' + (randomChar - 52)
        }
    }
    return String(nonce)
}

fun validate(
    key: String,
    value: String?,
    className: String
) {
    if (value == null || value == "null" || value.isEmpty()) {
        throw Logger.handleException(
            exceptionType = if (value == null) "MissingInput" else "InvalidInput",
            fieldPath = listOf(key),
            className = className,
            fieldType = "String"
        )
    }
}

inline fun <reified T> encodeToJsonString(data: T, fieldName: String, className: String): String {
    try {
        val objectMapper = jacksonObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL)
        return objectMapper.writeValueAsString(data)
    } catch (exception: Exception) {
        throw Logger.handleException(
            exceptionType = "JsonEncodingFailed",
            message = exception.message,
            fieldPath = listOf(fieldName),
            className = className
        )
    }
}

fun ByteArray.toHex(): String{
    return this.joinToString("") { "%02x".format(it) }
}
