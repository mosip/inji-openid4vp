package io.mosip.openID4VP.authorizationRequest.clientMetadata

import Generated
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.FieldsSerializer
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = Jwks::class.simpleName!!

object JwksSerializer : KSerializer<Jwks> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Jwks") {
        element<ArrayList<Jwk>>("keys", isOptional = true)
    }

    override fun deserialize(decoder: Decoder): Jwks {
        val jsonDecoder = try {
            decoder as JsonDecoder
        } catch (e: ClassCastException) {
            throw OpenID4VPExceptions.DeserializationFailure( listOf("jwk"),e.message!!, className )
        }
        val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
        val deserializer = FieldDeserializer(
            jsonObject = jsonObject, className = className, parentField = "jwk"
        )
        val keys: List<Jwk> = deserializer.deserializeField(
            key = "keys",
            fieldType = "List<Jwk>",
            deserializer = ListSerializer(Jwk.serializer()),
            isMandatory = false
        )!!
        return Jwks(keys = keys)
    }

    @Generated
    override fun serialize(encoder: Encoder, value: Jwks) {
        val builtInEncoder = encoder.beginStructure(FieldsSerializer.descriptor)
        builtInEncoder.encodeSerializableElement(
            descriptor,
            0,
            ListSerializer(Jwk.serializer()),
            value.keys
        )
        builtInEncoder.endStructure(FieldsSerializer.descriptor)
    }
}

@Serializable(with = JwksSerializer::class)
data class Jwks(
    val keys: List<Jwk>
)