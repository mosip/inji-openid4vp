
package io.mosip.openID4VP.dto

import Generated
import io.mosip.openID4VP.authorizationRequest.ClientIdScheme
import io.mosip.openID4VP.authorizationRequest.Validatable
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = WalletMetadata::class.simpleName!!

object WalletMetadataSerializer : KSerializer<WalletMetadata> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClientMetadata") {
        element<Boolean>("presentation_definition_uri_supported", isOptional = true)
        element<Map<String,VPFormatSupported>>("vp_formats_supported", isOptional = false)
        element<List<String>>("client_id_schemes_supported", isOptional = true)
        element<List<String>>("request_object_signing_alg_values_supported", isOptional = true)
        element<List<String>>("authorization_encryption_alg_values_supported", isOptional = true)
        element<List<String>>("authorization_encryption_enc_values_supported", isOptional = true)
    }

    override fun deserialize(decoder: Decoder): WalletMetadata {
        val jsonDecoder = try {
            decoder as JsonDecoder
        } catch (e: ClassCastException) {
            throw Logger.handleException(
                exceptionType = "DeserializationFailure",
                fieldPath = listOf("wallet_metadata"),
                message = e.message!!,
                className = className
            )
        }
        val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
        val deserializer = FieldDeserializer(
            jsonObject = jsonObject,
            className = className,
            parentField = "wallet_metadata"
        )

        val presentationDefinitionURISupported: Boolean? =
            deserializer.deserializeField(
                key = "presentation_definition_uri_supported",
                fieldType = "Boolean"
            )
        val vpFormatsSupported: Map<String, VPFormatSupported> =
            deserializer.deserializeField(key = "vp_formats_supported", fieldType = "Map", isMandatory = true)
                ?: throw Logger.handleException(
                    exceptionType = "InvalidInput",
                    fieldPath = listOf("wallet_metadata", "vp_formats_supported"),
                    className = className,
                    fieldType = "map",
                )
        val clientIdSchemesSupported: List<String>? =
            deserializer.deserializeField(key = "client_id_schemes_supported", fieldType = "List")
        val requestObjectSigningAlgValuesSupported: List<String>? =
            deserializer.deserializeField(key = "request_object_signing_alg_values_supported", fieldType = "List")
        val authorizationEncryptionAlgValuesSupported: List<String>? =
            deserializer.deserializeField(key = "authorization_encryption_alg_values_supported", fieldType = "List")
        val authorizationEncryptionEncValuesSupported: List<String>? =
            deserializer.deserializeField(key = "authorization_encryption_enc_values_supported", fieldType = "List")

        return WalletMetadata(
            presentationDefinitionURISupported = presentationDefinitionURISupported,
            vpFormatsSupported = vpFormatsSupported,
            clientIdSchemesSupported = clientIdSchemesSupported,
            requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported,
            authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported,
            authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
        )
    }

    @Generated
    override fun serialize(encoder: Encoder, value: WalletMetadata) {
        val builtInEncoder = encoder.beginStructure(descriptor)

        value.presentationDefinitionURISupported?.let {
            builtInEncoder.encodeBooleanElement(
                descriptor,
                0,
                it
            )
        }
        value.clientIdSchemesSupported?.let {
            builtInEncoder.encodeSerializableElement(
                descriptor,
                2,
                ListSerializer(String.serializer()),
                it
            )
        }
        value.requestObjectSigningAlgValuesSupported?.let {
            builtInEncoder.encodeSerializableElement(
                descriptor,
                3,
                ListSerializer(String.serializer()),
                it
            )
        }
        value.authorizationEncryptionAlgValuesSupported?.let {
            builtInEncoder.encodeSerializableElement(
                descriptor,
                4,
                ListSerializer(String.serializer()),
                it
            )
        }
        value.authorizationEncryptionEncValuesSupported?.let {
            builtInEncoder.encodeSerializableElement(
                descriptor,
                4,
                ListSerializer(String.serializer()),
                it
            )
        }
        builtInEncoder.endStructure(descriptor)
    }
}

@Serializable(with = WalletMetadataSerializer::class)
class WalletMetadata(

    @SerialName("presentation_definition_uri_supported")  val presentationDefinitionURISupported: Boolean? = true,
    @SerialName("vp_formats_supported") val vpFormatsSupported: Map<String, VPFormatSupported>,
    @SerialName("client_id_schemes_supported")val clientIdSchemesSupported: List<String>? = listOf(ClientIdScheme.PRE_REGISTERED.value),
    @SerialName("request_object_signing_alg_values_supported") val requestObjectSigningAlgValuesSupported: List<String>? = null,
    @SerialName("authorization_encryption_alg_values_supported") val authorizationEncryptionAlgValuesSupported: List<String>? = null,
    @SerialName("authorization_encryption_enc_values_supported") val authorizationEncryptionEncValuesSupported: List<String>? = null
) : Validatable {
    override fun validate() {
    }
}
@Serializable
data class VPFormatSupported(
    @SerialName("alg_values_supported") val algValuesSupported: List<String>?
)


