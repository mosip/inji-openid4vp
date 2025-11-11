package io.mosip.openID4VP.authorizationResponse

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
        val jsonObject =
            if (this.additionalParams.isNullOrBlank()) JSONObject() else JSONObject(this.additionalParams)
        this.redirectUri?.let {
            jsonObject.put("redirect_uri", it)
        }
        return jsonObject.toString()
    }
}


