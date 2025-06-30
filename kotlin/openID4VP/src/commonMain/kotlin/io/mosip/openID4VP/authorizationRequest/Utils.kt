package io.mosip.openID4VP.authorizationRequest

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

fun interface Validatable {
    fun validate()
}

fun <T : Validatable> deserializeAndValidate(
    paramJsonAsString: String, type: KSerializer<T>
): T {
    try {
        val deserializedValue: T = Json.decodeFromString(type, paramJsonAsString)
        deserializedValue.validate()

        return deserializedValue
    } catch (exception: Exception) {
        throw exception
    }
}

fun <T : Validatable> deserializeAndValidate(
    paramJsonAsString: Map<String, Any>, type: KSerializer<T>
): T {
    try {
        val objectMapper = jacksonObjectMapper()
        val rawJsonString = objectMapper.writeValueAsString(paramJsonAsString)

        val deserializedValue: T = Json.decodeFromString(type, rawJsonString)
        deserializedValue.validate()

        return deserializedValue
    } catch (exception: Exception) {
        throw exception
    }
}