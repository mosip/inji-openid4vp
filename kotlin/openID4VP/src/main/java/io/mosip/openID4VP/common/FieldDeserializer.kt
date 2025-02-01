package io.mosip.openID4VP.common

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.floatOrNull
import kotlinx.serialization.json.intOrNull

class FieldDeserializer(
	private val jsonObject: JsonObject,
	private val className: String,
	private val parentField: String
) {
	fun <T> deserializeField(
		key: String,
		fieldType: String,
		deserializer: DeserializationStrategy<T>? = null,
		isMandatory: Boolean = false,
	): T? {
		val data = jsonObject[key]

		//field is mandatory but it is not present in the input
		if (data == null && isMandatory) {
			throw Logger.handleException(
				exceptionType = "MissingInput",
				fieldPath = listOf(parentField, key),
				className = className
			)
		} else if (data == JsonNull) {
			throw Logger.handleException(
				exceptionType = "InvalidInput",
				fieldPath = listOf(parentField, key),
				className = className,
				fieldType = fieldType
			)
		}
		//field is mandatory or optional and it is present in the input
		if (data != null) {
			val res = when {
				deserializer != null -> Json.decodeFromJsonElement(
					deserializer,
					data
				) // Custom fields

				fieldType == "String" -> {
					validateFieldType(data, fieldType, parentField, key, className)
					(data as JsonPrimitive).content as T
				}

				fieldType == "Boolean" -> {
					validateFieldType(data, fieldType, parentField, key, className)
					(data as JsonPrimitive).boolean as T
				}

				fieldType.startsWith("List") -> Json.decodeFromJsonElement(
					ListSerializer(String.serializer()),
					data
				) as T

				fieldType.startsWith("Map") -> Json.decodeFromJsonElement<Map<String, JsonElement>>(data)
					.mapValues { (_, value) -> parseDynamicValue(value) } as T

				else -> throw SerializationException("Unsupported field type: $fieldType")
			}
			require(validateField(res, fieldType)) {
				throw Logger.handleException(
					exceptionType = "InvalidInput",
					fieldPath = listOf(parentField, key),
					className = className,
					fieldType = fieldType
				)
			}
			return res
		} else {
			return null
		}
	}

	fun parseDynamicValue(value: JsonElement): Any {
		return when {
			value is JsonPrimitive -> value.contentOrNull ?: value.booleanOrNull ?: value.intOrNull
			?: value.floatOrNull ?: value.doubleOrNull ?: value

			value is JsonArray -> value.map { parseDynamicValue(it) }
			value is JsonObject -> value.mapValues { parseDynamicValue(it.value) }
			else -> value
		}
	}

	private fun validateFieldType(
		data: JsonElement,
		fieldType: String,
		parentField: String,
		key: String,
		className: String
	) {
		if (data !is JsonPrimitive || when (fieldType) {
				"String" -> !data.isString
				"Boolean" -> !data.boolean
				else -> true
			}
		) {
			throw Logger.handleException(
				exceptionType = "InvalidInput",
				fieldPath = listOf(parentField, key),
				className = className,
				fieldType = fieldType
			)
		}
	}
}