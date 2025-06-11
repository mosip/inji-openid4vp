package io.mosip.sampleapp.data.api

import com.google.gson.JsonObject
import retrofit2.Response
import retrofit2.http.GET

interface AllPropertiesApi {
    @GET("v1/mimoto/allProperties")
    suspend fun getAllProperties(): Response<JsonObject>
}