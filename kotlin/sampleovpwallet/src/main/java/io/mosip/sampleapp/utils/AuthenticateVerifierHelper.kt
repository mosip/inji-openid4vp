package io.mosip.sampleapp.utils

import android.util.Log
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.google.gson.JsonObject
import io.mosip.openID4VP.authorizationRequest.WalletMetadata

object AuthenticateVerifierHelper {
    fun extractWalletMetadata(allProperties: JsonObject?): WalletMetadata {
        val hardcodedMetadataJson = """
    {
      "presentation_definition_uri_supported": true,
      "vp_formats_supported": {
        "ldp_vc": {
          "alg_values_supported": [
            "Ed25519Signature2018",
            "Ed25519Signature2020",
            "RSASignature2018"
          ]
        },
        "mso_mdoc": {
          "alg_values_supported": ["ES256"]
        }
      },
      "client_id_schemes_supported": ["redirect_uri", "did", "pre-registered"],
      "request_object_signing_alg_values_supported": ["EdDSA"],
      "authorization_encryption_alg_values_supported": ["ECDH-ES"],
      "authorization_encryption_enc_values_supported": ["A256GCM"]
    }
    """.trimIndent()

        val objectMapper = jacksonObjectMapper()

        return try {
            val walletMetadataJson = allProperties
                ?.getAsJsonPrimitive("walletMetadata")
                ?.asString

            if (!walletMetadataJson.isNullOrBlank()) {
                objectMapper.readValue(walletMetadataJson)
            } else {
                objectMapper.readValue(hardcodedMetadataJson)
            }
        } catch (e: Exception) {
            Log.e("WalletMetadata", "Failed to parse walletMetadata, returning hardcoded.", e)
            objectMapper.readValue(hardcodedMetadataJson)
        }
    }


    fun isClientValidationRequired(allProperties: JsonObject?): Boolean {
        return try {
            allProperties
                ?.getAsJsonPrimitive("openid4vpClientValidation")
                ?.asString
                ?.equals("true", ignoreCase = true) == true
        } catch (e: Exception) {
            false
        }
    }
}