package io.mosip.openID4VP.authorizationResponse

import org.json.JSONObject

data class VerifierResponse(
    val statusCode: Int,
    val redirectUri: String? = null,
    val additionalParams: String? = null,
    val headers: Map<String, List<String>>
) {
    fun isOk(): Boolean = statusCode in 200..299 // utility to check on success case
    internal fun composedBody(): String {
        val jsonObject =
            if (this.additionalParams.isNullOrBlank()) JSONObject() else JSONObject(this.additionalParams)
        this.redirectUri?.let {
            jsonObject.put("redirect_uri", it)
        }
        return jsonObject.toString()
    }
}


