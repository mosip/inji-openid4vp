package io.mosip.openID4VP.verifier

data class VerifierResponse(
    val statusCode: Int,
    // Holds redirect_uri from the Verifier response body
    val redirectUri: String? = null,
    // Holds additional parameters in JSON string format other than redirect_uri from the Verifier response body
    val additionalParams: String? = null,
    val headers: Map<String, List<String>>,
    private val responseBody: String = ""
) {
    fun isOk(): Boolean = statusCode in 200..299

    internal fun body(): String = responseBody

    override fun toString(): String {
        return "VerifierResponse(statusCode=$statusCode, redirectUri=$redirectUri, additionalParams=$additionalParams, headers=$headers)"
    }
}