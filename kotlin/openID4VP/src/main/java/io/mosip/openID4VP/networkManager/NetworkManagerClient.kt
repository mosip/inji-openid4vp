package io.mosip.openID4VP.networkManager

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.FormBody
import okhttp3.Headers
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.InterruptedIOException

private val logTag = Logger.getLogTag(NetworkManagerClient::class.simpleName!!)

class NetworkManagerClient {
	companion object {
		fun sendHTTPRequest(
			url: String,
			method: HTTP_METHOD,
			bodyParams: Map<String, String>? = null,
			headers: Map<String, String>? = null
		): Map<String, Any> {
			try {
				val client = OkHttpClient.Builder().build()
				val request: Request
				when (method) {
					HTTP_METHOD.POST -> {
						val requestBodyBuilder = FormBody.Builder()
						bodyParams?.forEach { (key, value) ->
							requestBodyBuilder.add(key, value)
						}
						val requestBody = requestBodyBuilder.build()
						val requestBuilder = Request.Builder().url(url).post(requestBody)
						headers?.forEach { (key, value) ->
							requestBuilder.addHeader(key, value)
						}
						request = requestBuilder.build()
					}

					HTTP_METHOD.GET -> request = Request.Builder().url(url).get().build()
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
				val specificException =
					NetworkManagerClientExceptions.NetworkRequestTimeout()
				Logger.error(logTag, specificException)
				throw specificException
			} catch (exception: Exception) {
				val specificException =
					NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
				Logger.error(logTag, specificException)
				throw specificException
			}
		}
	}
}

enum class HTTP_METHOD {
	POST, GET
}