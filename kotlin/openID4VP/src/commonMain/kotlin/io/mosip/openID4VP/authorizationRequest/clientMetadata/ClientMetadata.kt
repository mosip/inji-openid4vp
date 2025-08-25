package io.mosip.openID4VP.authorizationRequest.clientMetadata

import Generated
import io.mosip.openID4VP.common.FieldDeserializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.Validatable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = ClientMetadata::class.simpleName!!

object ClientMetadataSerializer : KSerializer<ClientMetadata> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClientMetadata") {
		element<String>("client_name", isOptional = true)
		element<String>("logo_uri", isOptional = true)
		element<Map<String, Map<String, List<String>>>>("vp_formats", isOptional = false)
		element<String>("authorization_encrypted_response_alg", isOptional = true)
		element<String>("authorization_encrypted_response_enc", isOptional = true)
		element<Jwks>("jwks", isOptional = true)
	}

	override fun deserialize(decoder: Decoder): ClientMetadata {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw  OpenID4VPExceptions.DeserializationFailure(
				listOf(CLIENT_METADATA.value),e.message!!,
				className)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject,
			className = className,
			parentField = CLIENT_METADATA.value
		)

		val clientName: String? =
			deserializer.deserializeField(key = "client_name", fieldType = "String")
		val logoUri: String? =
			deserializer.deserializeField(key = "logo_uri", fieldType = "String")
		val vpFormats: Map<String, Map<String, List<String>>> =
			deserializer.deserializeField<Map<String, Map<String, List<String>>>>(
				key = "vp_formats",
				fieldType = "Map"
			) ?: throw  OpenID4VPExceptions.InvalidInput(listOf(CLIENT_METADATA.value,"vp_formats"),"map",className)
		val authorizationEncryptedResponseAlg: String? =
			deserializer.deserializeField(key = "authorization_encrypted_response_alg", fieldType = "String")
		val authorizationEncryptedResponseEnc: String? =
			deserializer.deserializeField(
				key = "authorization_encrypted_response_enc",
				fieldType = "String"
			)
		val jwks: Jwks? = deserializer.deserializeField(
			key = "jwks",
			fieldType = "Jwks",
			deserializer = Jwks.serializer(),
			isMandatory = false
		)

		return ClientMetadata(
			clientName = clientName,
			logoUri = logoUri,
			vpFormats = vpFormats,
			authorizationEncryptedResponseAlg = authorizationEncryptedResponseAlg,
			authorizationEncryptedResponseEnc = authorizationEncryptedResponseEnc,
			jwks = jwks,
		)
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
		builtInEncoder.encodeSerializableElement(
			descriptor,
			2,
			MapSerializer(
				String.serializer(),
				MapSerializer(
					String.serializer(),
					ListSerializer(String.serializer())
				)
			),
			value.vpFormats
		)
		value.authorizationEncryptedResponseAlg?.let { builtInEncoder.encodeStringElement(descriptor, 3, it) }
		value.authorizationEncryptedResponseEnc?.let { builtInEncoder.encodeStringElement(descriptor, 4, it) }
		value.jwks?.let { builtInEncoder.encodeSerializableElement(
			descriptor, 5, Jwks.serializer(), value.jwks
		) }
		builtInEncoder.endStructure(descriptor)
	}
}


@Serializable(with = ClientMetadataSerializer::class)
class ClientMetadata(
	@SerialName("client_name") val clientName: String? = null,
	@SerialName("logo_uri") val logoUri: String? = null,
	@SerialName("vp_formats") val vpFormats: Map<String, Map<String, List<String>>>,
	@SerialName("authorization_encrypted_response_alg") val authorizationEncryptedResponseAlg: String? = null,
	@SerialName("authorization_encrypted_response_enc") val authorizationEncryptedResponseEnc: String? = null,
	@SerialName("jwks") val jwks: Jwks? = null,
) : Validatable {
	override fun validate() {
		if(vpFormats.isEmpty())	{
			throw OpenID4VPExceptions.InvalidInput(
				listOf(CLIENT_METADATA.value,"vp_formats"),"map",
				className)
		}
		return
	}
}