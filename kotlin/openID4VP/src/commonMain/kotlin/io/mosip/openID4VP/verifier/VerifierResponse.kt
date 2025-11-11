package io.mosip.openID4VP.verifier

import org.json.JSONObject

data class VerifierResponse(
    val statusCode: Int,
    // Holds redirect_uri from the Verifier response body
    val redirectUri: String? = null,
    // Holds additional parameters in JSON string format other than redirect_uri from the Verifier response body
    val additionalParams: String? = null,
    val headers: Map<String, List<String>>
) {
    fun isOk(): Boolean = statusCode in 200..299
    internal fun composedBody(): String {
        if (redirectUri == null) {
            return additionalParams.orEmpty()
        }
        return try {
            val jsonObject = if (additionalParams.isNullOrBlank()) JSONObject() else JSONObject(additionalParams)
            jsonObject.put("redirect_uri", redirectUri)
            jsonObject.toString()
        } catch (_: Exception) {
            additionalParams.orEmpty()
        }
    }
}