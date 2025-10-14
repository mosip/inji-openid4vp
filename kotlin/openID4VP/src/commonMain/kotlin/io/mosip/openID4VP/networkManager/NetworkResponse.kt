package io.mosip.openID4VP.networkManager

data class NetworkResponse(val statusCode: Int, val body: String, val headers: Map<String, List<String>>) {
    fun isOk(): Boolean = statusCode in 200..299
}
