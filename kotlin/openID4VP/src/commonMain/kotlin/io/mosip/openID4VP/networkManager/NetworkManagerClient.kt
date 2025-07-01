package io.mosip.openID4VP.networkManager

import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
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
        ): Map<String, Any> {
            try {
                val client = OkHttpClient.Builder().build()
                val request: Request = when (method) {
                    HttpMethod.POST -> {
                        val requestBodyBuilder = FormBody.Builder()
                        bodyParams?.forEach { (key, value) ->
                            requestBodyBuilder.add(key, value)
                        }
                        val requestBody = requestBodyBuilder.build()
                        val requestBuilder = Request.Builder().url(url).post(requestBody)
                        headers?.forEach { (key, value) ->
                            requestBuilder.addHeader(key, value)
                        }
                        requestBuilder.build()
                    }
                    HttpMethod.GET -> Request.Builder().url(url).get().build()
                }

                val response: Response = client.newCall(request).execute()

                if (response.isSuccessful) {
                    val body = response.body?.byteStream()?.bufferedReader().use { it?.readText() }
                        ?: ""

                    return mapOf(
                        "body" to body,
                        "header" to response.headers
                    )
                } else {
                    throw Exception(response.toString())
                }
            } catch (exception: InterruptedIOException) {
                val specificException = NetworkManagerClientExceptions.NetworkRequestTimeout()
                Logger.getLogger(logTag()).log(Level.SEVERE,"ERROR | Timeout occurred: ${specificException.message}")
                throw specificException
            } catch (exception: Exception) {
                val specificException = NetworkManagerClientExceptions.NetworkRequestFailed(
                    exception.message ?: "Unknown error"
                )
                Logger.getLogger(logTag()).log(Level.SEVERE,"ERROR | Request failed: ${specificException.message}")
                throw specificException
            }
        }
    }
}
