package io.mosip.sampleapp.data

import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ContentEncryptionAlgorithm
import io.mosip.openID4VP.constants.KeyManagementAlgorithm
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.constants.VPFormatType

object HardcodedOVPData {
    fun getWalletMetadata(): WalletMetadata {
        return WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("Ed25519Signature2018", "Ed25519Signature2020", "RSASignature2018")
                ),
                VPFormatType.MSO_MDOC to VPFormatSupported(
                    algValuesSupported = listOf("ES256")
                )
            ),
            clientIdSchemesSupported = listOf(ClientIdScheme.REDIRECT_URI, ClientIdScheme.DID, ClientIdScheme.PRE_REGISTERED),
            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
            authorizationEncryptionEncValuesSupported = listOf(ContentEncryptionAlgorithm.A256GCM)
        )
    }

    fun getListOfVerifiers(): List<Verifier> {
        val hardcodedVerifierJson = """
        [
            {
              "client_id": "https://localhost:3000",
              "response_uris": [
                "https://localhost:3000/v1/verify/vp-submission/direct-post"
              ]
            }
        ]
    """.trimIndent()

        val objectMapper = jacksonObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)

        return objectMapper.readValue(hardcodedVerifierJson)
    }
}