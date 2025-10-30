package io.mosip.openID4VP.networkManager

import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import java.io.InterruptedIOException
import java.util.logging.Level
import java.util.logging.Logger

class NetworkManagerClient {
    companion object {

        private fun logTag(): String =
            "INJI-OpenID4VP : class name - ${NetworkManagerClient::class.simpleName}"

        fun sendHTTPRequest(
            url: String,
            method: HttpMethod,
            bodyParams: Map<String, String>? = null,
            headers: Map<String, String>? = null
        ): NetworkResponse {
            try {
                val client = OkHttpClient.Builder().build()
                val requestBody = requestBody(bodyParams)

                val requestBuilder = Request.Builder().url(url).method(method.name, requestBody)
                addHeaders(headers, requestBuilder)
                val request = requestBuilder.build()

                val response: Response = client.newCall(request).execute()

                return response.use {
                    val headersMap = it.headers.toMultimap()
                    val body = it.body?.string().orEmpty()
                    NetworkResponse(it.code, body, headersMap)
                }
            } catch (exception: InterruptedIOException) {
                val specificException = NetworkManagerClientExceptions.NetworkRequestTimeout()
                Logger.getLogger(logTag())
                    .log(Level.SEVERE, "ERROR | Timeout occurred: ${specificException.message}")
                throw specificException
            } catch (exception: Exception) {
                val specificException = NetworkManagerClientExceptions.NetworkRequestFailed(
                    exception.message ?: "Unknown error"
                )
                Logger.getLogger(logTag())
                    .log(Level.SEVERE, "ERROR | Request failed: ${specificException.message}")
                throw specificException
            }
        }

        private fun requestBody(bodyParams: Map<String, String>?): RequestBody? {
            if (bodyParams == null) return null

            val requestBodyBuilder = FormBody.Builder()
            bodyParams.forEach { (key, value) ->
                requestBodyBuilder.add(key, value)
            }
            return requestBodyBuilder.build()
        }

        private fun addHeaders(
            headers: Map<String, String>?,
            requestBuilder: Request.Builder
        ) {
            headers?.forEach { (key, value) ->
                requestBuilder.addHeader(key, value)
            }
        }
    }
}
