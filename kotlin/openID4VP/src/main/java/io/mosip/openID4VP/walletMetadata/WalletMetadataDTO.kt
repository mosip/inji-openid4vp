import org.json.JSONObject

data class WalletMetadata(
    val presentationDefinitionURISupported: Boolean? = true,
    val vpFormatsSupported: Map<String, VPFormatSupported>,
    val clientIDSchemesSupported: List<ClientIdScheme>? = listOf(ClientIdScheme.PRE_REGISTERED)
) {
    companion object {
        fun validate(jsonString: String) {
            if (jsonString.isBlank()) throw ValidationError.InvalidJSON

            try {
                val jsonObject = JSONObject(jsonString)

                val allowedKeys = setOf("presentationDefinitionURISupported", "vpFormatsSupported", "clientIDSchemesSupported")

                for (key in jsonObject.keys()) {
                    if (!allowedKeys.contains(key)) {
                        throw ValidationError.ExtraField(key)
                    }
                }

                if (!jsonObject.has("vpFormatsSupported")) {
                    throw ValidationError.MissingRequiredField("vpFormatsSupported")
                }

            } catch (exception: Exception) {
                throw ValidationError.InvalidJSON
            }
        }
    }
}

data class VPFormatSupported(
    val algValuesSupported: List<String>?
)

enum class ClientIdScheme {
    PRE_REGISTERED, REDIRECT_URI, HTTPS, DID
}

