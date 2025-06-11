package io.mosip.sampleapp.data.repository

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import io.mosip.sampleapp.data.network.NetworkHelper

class VerifierRepository {
    private val api = NetworkHelper.verifierApi

    suspend fun fetchVerifiers(): List<JsonObject>? {
        return try {
            val response = api.getVerifiers()
            if (response.isSuccessful) {
                val json = response.body()
                val verifiersJsonArray: JsonArray? = json?.getAsJsonObject("response")?.getAsJsonArray("verifiers")

                verifiersJsonArray?.map { it.asJsonObject }
            } else null
        } catch (e: Exception) {
            null
        }
    }
}