package io.mosip.openID4VP.responseModeHandler.types

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.ClientIdScheme.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.authorizationResponse
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.walletMetadata
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DirectPostJwtResponseModeHandlerTest {

    @BeforeTest
    fun setUp() {

        mockkObject(NetworkManagerClient)
        mockkConstructor(JWEHandler::class)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    /** validation of client metadata **/

    @Test
    fun `should validate the mandatory fields of clientMetadata`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
    }

    @Test
    fun `should throw error if jwks field is missing in clientMetadata`() {
        val clientMetadataStr = """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","vp_formats":{"ldp_vp":{"proof_type":["Ed25519Signature2018"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals("Missing Input: client_metadata->jwks param is required", exception.message)
    }

    @Test
    fun `should throw error if authorization_encrypted_response_enc field is missing in clientMetadata`() {
        val clientMetadataStr = """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","vp_formats":{"ldp_vp":{"proof_type":["Ed25519Signature2018"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals("Missing Input: client_metadata->authorization_encrypted_response_enc param is required", exception.message)
    }

    @Test
    fun `should throw error if authorization_encrypted_response_alg field is missing in clientMetadata`() {
        val clientMetadataStr = """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_enc":"A256GCM","vp_formats":{"ldp_vp":{"proof_type":["Ed25519Signature2018"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals("Missing Input: client_metadata->authorization_encrypted_response_alg param is required", exception.message)
    }

    @Test
    fun `should throw error if no jwk matching the key encryption algorithm is found`() {
        val clientMetadataStr = """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{"alg":["ES256"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals("No jwk matching the specified algorithm found for encryption", exception.message)
    }

    @Test
    fun `should throw error if no jwk matching the use key is found`() {
        val clientMetadataStr = """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"sign","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{"alg":["ES256"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals("No jwk matching the specified algorithm found for encryption", exception.message)
    }

    @Test
    fun `should validate the fields of clientMetadata with walletMetadata`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
    }

    @Test
    fun `should throw error if the key exchange algorithm does not match supported list from the walletMetadata`() {
        val clientMetadataStr = """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{},"ldp_vc":{"proof_type":["Ed25519Signature2018","Ed25519Signature2020"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }
        assertEquals("authorization_encrypted_response_alg is not supported", exception.message)
    }

    @Test
    fun `should throw error if the key exchange algorithm supported list is not provided by wallet`() {
        val invalidWalletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf("ldp_vc" to VPFormatSupported(algValuesSupported = listOf("RSA"))),
            clientIdSchemesSupported = listOf(REDIRECT_URI.value, DID.value, PRE_REGISTERED.value),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, invalidWalletMetadata, true)
        }
        assertEquals("authorization_encryption_alg_values_supported must be present in wallet_metadata", exception.message)
    }

    @Test
    fun `should throw error if the encryption algorithm does not match supported list from the walletMetadata`() {
        val clientMetadataStr = """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{},"ldp_vc":{"proof_type":["Ed25519Signature2018","Ed25519Signature2020"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }
        assertEquals("authorization_encrypted_response_enc is not supported", exception.message)
    }

    @Test
    fun `should throw error if the encryption algorithm supported list is not provided by wallet`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        val invalidWalletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf("ldp_vc" to VPFormatSupported(algValuesSupported = listOf("RSA"))),
            clientIdSchemesSupported = listOf(REDIRECT_URI.value, DID.value, PRE_REGISTERED.value),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = null
        )

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, invalidWalletMetadata, true)
        }
        assertEquals("authorization_encryption_enc_values_supported must be present in wallet_metadata", exception.message)
    }

    /** sending of authorization response **/

    @Test
    fun `should send the authorization response with JWE in requestBody successfully`() {
        val responseUri = "https://mock-verifier.com/response"
        val vpShareSuccessResponse = "VP shared successfully"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to vpShareSuccessResponse)

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns "eytyiewr.....jewjr"

        val actualResponse = DirectPostJwtResponseModeHandler().sendAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            responseUri,
            authorizationResponse,
            "walletNonce"
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = responseUri,
                method = HttpMethod.POST,
                bodyParams = mapOf("response" to "eytyiewr.....jewjr"),
                headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
            )
        }
        assertEquals(vpShareSuccessResponse, actualResponse)
    }
}