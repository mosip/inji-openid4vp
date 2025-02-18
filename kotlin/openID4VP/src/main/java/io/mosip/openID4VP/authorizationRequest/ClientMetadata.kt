package io.mosip.openID4VP.authorizationRequest

import Generated
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = ClientMetadata::class.simpleName!!

object ClientMetadataSerializer : KSerializer<ClientMetadata> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClientMetadata") {
		element<String>("client_name", isOptional = true)
		element<String>("logo_uri", isOptional = true)
	}

	override fun deserialize(decoder: Decoder): ClientMetadata {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw Logger.handleException(
				exceptionType = "DeserializationFailure",
				fieldPath = listOf("client_metadata"),
				message = e.message!!,
				className = className
			)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject,
			className = className,
			parentField = "client_metadata"
		)

		val clientName: String? =
			deserializer.deserializeField(key = "client_name", fieldType = "String")
		val logoUri: String? =
			deserializer.deserializeField(key = "logo_uri", fieldType = "String")

		return ClientMetadata(clientName = clientName, logoUri = logoUri)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: ClientMetadata) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		value.clientName?.let {
			builtInEncoder.encodeStringElement(
				descriptor,
				0,
				value.clientName
			)
		}
		value.logoUri?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = ClientMetadataSerializer::class)
class ClientMetadata(
	@SerialName("client_name") val clientName: String?,
	@SerialName("logo_uri") val logoUri: String?
) :
	Validatable {
	override fun validate() {
	}
}