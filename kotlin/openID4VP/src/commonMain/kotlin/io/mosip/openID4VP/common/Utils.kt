package io.mosip.openID4VP.common

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import java.security.MessageDigest
import java.security.SecureRandom

private const val URL_PATTERN = "^https://(?:[\\w-]+\\.)+[\\w-]+(?:/[\\w\\-.~!$&'()*+,;=:@%]+)*/?(?:\\?[^#\\s]*)?(?:#.*)?$"

fun isValidUrl(url : String): Boolean {
    return url.matches(URL_PATTERN.toRegex())
}

fun convertJsonToMap(jsonString: String): MutableMap<String, Any> {
    return getObjectMapper().readValue(
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
        else -> throw IllegalArgumentException("Unsupported HTTP method: $method")
    }
}

fun getStringValue(params: Map<String, Any>, key: String): String? {
    return params[key]?.toString()
}

fun generateNonce(minEntropy: Int = 16): String {
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
    className: String,
    fieldType: String = "String"
) {
    if (value == null || value == "null" || value.isEmpty()) {
        throw if(value == null) {
            OpenID4VPExceptions.MissingInput(listOf(key),"",className)
        } else {
            OpenID4VPExceptions.InvalidInput(listOf(key), fieldType, className)
        }
    }
}

inline fun <reified T> encodeToJsonString(data: T, fieldName: String, className: String): String {
    try {
        val objectMapper = jacksonObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL)
        return objectMapper.writeValueAsString(data)
    } catch (exception: Exception) {
        throw  OpenID4VPExceptions.JsonEncodingFailed(listOf(fieldName), exception.message.toString(),className)
    }
}

fun ByteArray.toHex(): String{
    return this.joinToString("") { "%02x".format(it) }
}

fun getObjectMapper(): ObjectMapper {
    return JacksonObjectMapper.instance
}

fun hashData(data: String, algorithm: String = "SHA-256"): String {
    val digest = MessageDigest.getInstance(algorithm)
    val hash = digest.digest(data.toByteArray(Charsets.UTF_8))
    return encodeToBase64Url(hash)
}

fun createNestedPath(inputDescriptorId: String, nestedPath: String?, format: FormatType): PathNested? {
    if (nestedPath == null) return null
    return PathNested(
        id = inputDescriptorId,
        format = format.value,
        path = nestedPath
    )
}

fun createDescriptorMapPath(vpIndex: Int) = "$[$vpIndex]"

internal fun resolveJwksFromUri(jwksUri: String, className: String): Jwks {
    return try {
        val response: NetworkResponse =
            NetworkManagerClient.sendHTTPRequest(jwksUri, HttpMethod.GET)

        if (!response.isOk()) {
            throw InvalidData(
                "Error while fetching jwks information, status code: ${response.statusCode} with body: ${response.body}",
                className
            )
        }

        getObjectMapper().readValue(response.body, Jwks::class.java)
    } catch (e: Exception) {
        throw InvalidData(
            "Public key extraction failed - Unable to fetch/parse jwks from $jwksUri due to ${e.message}",
            className,
            OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
        )
    }
}