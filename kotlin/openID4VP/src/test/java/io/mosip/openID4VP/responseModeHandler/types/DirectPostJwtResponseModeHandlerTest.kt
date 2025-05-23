package io.mosip.openID4VP.responseModeHandler.types


import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.ClientIdScheme.*
import io.mosip.openID4VP.exceptions.Exceptions.InvalidData
import io.mosip.openID4VP.exceptions.Exceptions.MissingInput
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.authorizationResponse
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.walletMetadata
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.assertThrows

class DirectPostJwtResponseModeHandlerTest {

    @Before
    fun setUp() {
        mockkStatic(android.util.Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
        every { Log.d(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }

        mockkObject(NetworkManagerClient)
        mockkConstructor(JWEHandler::class)
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    /** validation of client metadata **/

    @Test
    fun `should validate the mandatory fields of clientMetadata`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        assertDoesNotThrow{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
    }

    @Test
    fun `should thrown error if jwks field is missing in clientMetadata` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exceptionMessage = "Missing Input: client_metadata->jwks param is required"
        val exception =assertThrows<MissingInput>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(exceptionMessage, exception.message)
    }

    @Test
    fun `should thrown error if authorization_encrypted_response_enc field is missing in clientMetadata` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exceptionMessage = "Missing Input: client_metadata->authorization_encrypted_response_enc param is required"
        val exception =assertThrows<MissingInput>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(exceptionMessage, exception.message)
    }

    @Test
    fun `should thrown error if authorization_encrypted_response_alg field is missing in clientMetadata` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exceptionMessage = "Missing Input: client_metadata->authorization_encrypted_response_alg param is required"
        val exception =assertThrows<MissingInput>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(exceptionMessage, exception.message)
    }

    @Test
    fun `should thrown error if no jwk matching the key encryption algorithm is found` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exceptionMessage = "No jwk matching the specified algorithm found for encryption"
        val exception =assertThrows<InvalidData>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(exceptionMessage, exception.message)
    }

    @Test
    fun `should thrown error if no jwk matching the use key is found` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"sign\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exceptionMessage = "No jwk matching the specified algorithm found for encryption"
        val exception =assertThrows<InvalidData>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(exceptionMessage, exception.message)
    }

    @Test
    fun `should validate the fields of clientMetadata with walletMetadata` (){
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        assertDoesNotThrow{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }
    }

    @Test
    fun `should throw error if the key exchange algorithm does not match supported list from the walletMetadata `() {
        val clientMetadataString =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{},\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}}}"

        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)

        val expectedExceptionMessage =
            "authorization_encrypted_response_alg is not supported"

        val exception = assertThrows<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }

        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error if the key exchange algorithm supported list is not provided by wallet and response mode is direct_post_jwt`() {
        val invalidWalletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("RSA")
                )
            ),
            clientIdSchemesSupported = listOf(
                REDIRECT_URI.value,
                DID.value,
                PRE_REGISTERED.value
            ),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        val expectedExceptionMessage =
            "authorization_encryption_alg_values_supported must be present in wallet_metadata"

        val exception = assertThrows<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, invalidWalletMetadata, true)
        }

        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error if the encryption algorithm does not match supported list from the walletMetadata `() {
        val clientMetadataString =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{},\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)


        val expectedExceptionMessage =
            "authorization_encrypted_response_enc is not supported"

        val exception = assertThrows<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }

        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error if the encryption algorithm supported list is not provided by wallet and response mode is direct_post_jwt`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        val invalidWalletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("RSA")
                )
            ),
            clientIdSchemesSupported = listOf(
                REDIRECT_URI.value,
                DID.value,
                PRE_REGISTERED.value
            ),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = null
        )
        val expectedExceptionMessage =
            "authorization_encryption_enc_values_supported must be present in wallet_metadata"

        val exception = assertThrows<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, invalidWalletMetadata, true)
        }

        assertEquals(expectedExceptionMessage, exception.message)
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

        val actualResponse =
            DirectPostJwtResponseModeHandler().sendAuthorizationResponse(
                authorizationRequestForResponseModeJWT, responseUri,
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