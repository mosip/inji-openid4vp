package io.mosip.sampleapp.data.api

import com.google.gson.JsonObject
import retrofit2.Response
import retrofit2.http.GET

interface VerifierApi {
    @GET("v1/mimoto/verifiers")
    suspend fun getVerifiers(): Response<JsonObject>
}