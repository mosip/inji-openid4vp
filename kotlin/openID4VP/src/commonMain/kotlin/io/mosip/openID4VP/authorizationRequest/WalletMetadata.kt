package io.mosip.openID4VP.authorizationRequest

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.constants.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

data class WalletMetadata(
    @JsonProperty("presentation_definition_uri_supported")
    val presentationDefinitionURISupported: Boolean = true,

    @JsonProperty("vp_formats_supported")
    var vpFormatsSupported: Map<VPFormatType, VPFormatSupported>? = getDefaultVpFormatsSupported(),

    @JsonProperty("client_id_schemes_supported")
    var clientIdSchemesSupported: List<ClientIdScheme>? = getDefaultClientIdSchemesSupported(),

    @JsonProperty("request_object_signing_alg_values_supported")
    var requestObjectSigningAlgValuesSupported: List<RequestSigningAlgorithm>? = getDefaultRequestSigningAlgorithmSupported(),

    @JsonProperty("authorization_encryption_alg_values_supported")
    var authorizationEncryptionAlgValuesSupported: List<KeyManagementAlgorithm>? = getDefaultKeyManagementAlgorithmSupported(),

    @JsonProperty("authorization_encryption_enc_values_supported")
    var authorizationEncryptionEncValuesSupported: List<ContentEncryptionAlgorithm>? = getDefaultContentEncryptionAlgorithmSupported(),

    @JsonProperty("response_types_supported")
    var responseTypeSupported: List<ResponseType>? = getDefaultResponseTypeSupported()
) {
    companion object {
        private val className = WalletMetadata::class.simpleName!!

        fun <T : Enum<T>> parseEnum(
            value: String,
            validEntries: Array<T>,
            typeName: String
        ): T {
            return validEntries.find { it.name == value } ?: throw OpenID4VPExceptions.InvalidData(
                "Invalid $typeName value: $value",
                className
            )
        }
    }

    constructor(): this(
        presentationDefinitionURISupported = true,
        vpFormatsSupported = getDefaultVpFormatsSupported(),
        clientIdSchemesSupported = getDefaultClientIdSchemesSupported(),
        requestObjectSigningAlgValuesSupported = getDefaultRequestSigningAlgorithmSupported(),
        authorizationEncryptionAlgValuesSupported = getDefaultKeyManagementAlgorithmSupported(),
        authorizationEncryptionEncValuesSupported = getDefaultContentEncryptionAlgorithmSupported(),
        responseTypeSupported = getDefaultResponseTypeSupported()
    )

    @Deprecated("This constructor accepts all field type as String, use the new constructor instead.")
    constructor(
        presentationDefinitionURISupported: Boolean = true,
        vpFormatsSupported: Map<String, VPFormatSupported>,
        clientIdSchemesSupported: List<String>? = null,
        requestObjectSigningAlgValuesSupported: List<String>? = null,
        authorizationEncryptionAlgValuesSupported: List<String>? = null,
        authorizationEncryptionEncValuesSupported: List<String>? = null,
    ) : this(
        presentationDefinitionURISupported = presentationDefinitionURISupported,
        vpFormatsSupported = vpFormatsSupported.mapKeys { key ->
            parseEnum(key.key, VPFormatType.entries.toTypedArray(), "VPFormatType")
        },
        clientIdSchemesSupported = clientIdSchemesSupported?.map {
            parseEnum(it, ClientIdScheme.entries.toTypedArray(), "ClientIdScheme")
        },
        requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported?.map {
            parseEnum(it, RequestSigningAlgorithm.entries.toTypedArray(), "RequestSigningAlgorithm")
        },
        authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported?.map {
            parseEnum(it, KeyManagementAlgorithm.entries.toTypedArray(), "KeyManagementAlgorithm")
        },
        authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported?.map {
            parseEnum(it, ContentEncryptionAlgorithm.entries.toTypedArray(), "ContentEncryptionAlgorithm")
        }
    )
}

data class VPFormatSupported(
    @JsonProperty("alg_values_supported") val algValuesSupported: List<String>? = null
)