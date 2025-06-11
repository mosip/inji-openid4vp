package io.mosip.sampleapp.data.network

import io.mosip.sampleapp.data.api.AllPropertiesApi
import io.mosip.sampleapp.data.api.VerifierApi
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor

object NetworkHelper {
    private const val BASE_URL = "https://api.qa-inji1.mosip.net/"

    private val retrofit: Retrofit by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }

    val verifierApi: VerifierApi by lazy {
        retrofit.create(VerifierApi::class.java)
    }

    val allPropertiesApi: AllPropertiesApi by lazy {
        retrofit.create(AllPropertiesApi::class.java)
    }
}