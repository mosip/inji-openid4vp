package io.mosip.sampleapp.data.repository

import com.google.gson.JsonObject
import io.mosip.sampleapp.data.network.NetworkHelper

class AllPropertiesRepository {
    private val api = NetworkHelper.allPropertiesApi

    suspend fun fetchAllProperties(): JsonObject? {
        return try {
            val response = api.getAllProperties()
            if (response.isSuccessful) {
                response.body()?.getAsJsonObject("response")
            } else null
        } catch (e: Exception) {
            null
        }
    }

}