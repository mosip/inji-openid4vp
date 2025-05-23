package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.authorizationRequest.clientMetadata.parseAndValidateClientMetadata
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.*
import io.mosip.openID4VP.constants.ResponseMode.*
import io.mosip.openID4VP.exceptions.Exceptions.InvalidData
import io.mosip.openID4VP.exceptions.Exceptions.InvalidInput
import io.mosip.openID4VP.exceptions.Exceptions.MissingInput
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.walletMetadata
import kotlinx.serialization.json.Json
import org.assertj.core.api.Assertions.assertThat
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.assertThrows

class ClientMetadataTest {
    private lateinit var actualException: Exception

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should parse client metadata successfully`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to clientMetadataString,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        assertDoesNotThrow {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        }
    }

    @Test
    fun `should throw invalid input exception if vp_formats field is not available`() {
        val invalidClientMetadata =
            "{\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\"}"

        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST.value
        )
        val expectedExceptionMessage =
            "Invalid Input: client_metadata->vp_formats value cannot be empty or null"

        actualException =
            Assert.assertThrows(InvalidInput::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }

        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }
    @Test
    fun `should throw invalid input exception if vp_formats field is empty map`() {
        val invalidClientMetadata =
            "{\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\", \"vp_formats\":{}}"

        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST.value
        )
        val expectedExceptionMessage =
            "Invalid Input: client_metadata->vp_formats value cannot be empty or null"

        actualException =
            Assert.assertThrows(InvalidInput::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }

        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if name field is available in client_metadata but the value is empty`() {
        val invalidClientMetadata =
            "{\"client_name\":\"\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"

        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST.value
        )

        val expectedExceptionMessage =
            "Invalid Input: client_metadata->client_name value cannot be an empty string, null, or an integer"

        actualException =
            Assert.assertThrows(InvalidInput::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }

        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if name field is available in client_metadata but the value is null`() {

        val invalidClientMetadata =
            "{\"client_name\":null,\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"

        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST.value
        )

        val expectedExceptionMessage =
            "Invalid Input: client_metadata->client_name value cannot be an empty string, null, or an integer"

        actualException =
            Assert.assertThrows(InvalidInput::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }

        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if log_url field is available in client_metadata but the value is empty`() {
        val invalidClientMetadata =
            "{\"client_name\":\"\",\"client_name\":\"verifier\",\"logo_uri\":\"\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"

        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )

        val expectedExceptionMessage =
            "Invalid Input: client_metadata->logo_uri value cannot be an empty string, null, or an integer"

        actualException =
            Assert.assertThrows(InvalidInput::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }

        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw missing input exception if encryption algorithm is missing for response mode is direct_post jwt`() {
        val invalidClientMetadata =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"EdDSA\"]}}}"
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        val expectedExceptionMessage =
            "Missing Input: client_metadata->authorization_encrypted_response_alg param is required"

        actualException =
            Assert.assertThrows(MissingInput::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }

        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw missing input exception if encryption encoding value is missing for response mode is direct_post jwt`() {
        val invalidClientMetadata =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"EdDSA\"]}}}"
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        val expectedExceptionMessage =
            "Missing Input: client_metadata->authorization_encrypted_response_enc param is required"

        actualException =
            Assert.assertThrows(MissingInput::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }
        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw missing input exception if jwks field is missing for response mode is direct_post jwt`() {
        val invalidClientMetadata =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"AES256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"EdDSA\"]}}}"
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        val expectedExceptionMessage =
            "Missing Input: client_metadata->jwks param is required"

        actualException =
            Assert.assertThrows(MissingInput::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }
        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw missing input exception if jwk matching the algorithm field is missing in jwks for response mode is direct_post jwt`() {
        val invalidClientMetadata =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"authorization_encrypted_response_alg\":\"ECDH\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"EdDSA\"]}}}"
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        val expectedExceptionMessage =
            "No jwk matching the specified algorithm found for encryption"

        actualException =
            Assert.assertThrows(InvalidData::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }
        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw InvalidData exception if client metadata is not of string or map type`() {
        val invalidClientMetadata = true
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to invalidClientMetadata,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        val expectedExceptionMessage =
            "client_metadata must be of type String or Map"

        actualException =
            Assert.assertThrows(InvalidData::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }
        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw InvalidData exception if client metadata is not present for response mode direct_post jwt`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        val expectedExceptionMessage =
            "client_metadata must be present for given response mode"

        actualException =
            Assert.assertThrows(InvalidData::class.java) {
                parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
            }
        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should not throw any exception if client metadata is not present for response mode direct_post`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            RESPONSE_MODE.value to DIRECT_POST.value
        )
        assertDoesNotThrow {
            parseAndValidateClientMetadata(authorizationRequestParam, false, walletMetadata)
        }
    }

    @Test
    fun `should validate the clientMetadata with the walletMetadata successfully`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to clientMetadataString,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )
        parseAndValidateClientMetadata(authorizationRequestParam, true, walletMetadata)
    }

    @Test
    fun `should throw error if the key exchange algorithm does not match supported list from the walletMetadata `() {
        val clientMetadataString =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{},\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}}}"
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to clientMetadataString,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )

        val expectedExceptionMessage =
            "authorization_encrypted_response_alg is not supported"

        val exception = assertThrows<InvalidData> {
            parseAndValidateClientMetadata(authorizationRequestParam, true,walletMetadata)
        }

        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error if the key exchange algorithm supported list is not provided by wallet and response mode is direct_post_jwt`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to clientMetadataString,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )

        val invalidWalletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("RSA")
                )
            ),
            clientIdSchemesSupported = listOf(
                ClientIdScheme.REDIRECT_URI.value,
                DID.value,
                PRE_REGISTERED.value
            ),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        val expectedExceptionMessage =
            "authorization_encryption_alg_values_supported must be present in wallet_metadata"

        val exception = assertThrows<InvalidData> {
            parseAndValidateClientMetadata(authorizationRequestParam, true, invalidWalletMetadata)
        }

        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error if the encryption algorithm does not match supported list from the walletMetadata `() {
        val clientMetadataString =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{},\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}}}"
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to clientMetadataString,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )

        val expectedExceptionMessage =
            "authorization_encrypted_response_enc is not supported"

        val exception = assertThrows<InvalidData> {
            parseAndValidateClientMetadata(authorizationRequestParam, true, walletMetadata)
        }

        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error if the encryption algorithm supported list is not provided by wallet and response mode is direct_post_jwt`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            CLIENT_METADATA.value to clientMetadataString,
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )

        val invalidWalletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("RSA")
                )
            ),
            clientIdSchemesSupported = listOf(
                ClientIdScheme.REDIRECT_URI.value,
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
            parseAndValidateClientMetadata(authorizationRequestParam,true, invalidWalletMetadata)
        }

        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should serialize clientMetadata correctly with all fields`() {
        val clientMetadata = ClientMetadata(
            clientName = "Requestername",
            logoUri = "<logo_uri>",
            authorizationEncryptedResponseAlg = "ECDH-ES",
            authorizationEncryptedResponseEnc = "A256GCM",
            vpFormats = mapOf(
                "mso_mdoc" to mapOf("alg" to listOf("ES256", "EdDSA")),
                "ldp_vp" to mapOf(
                    "proof_type" to listOf(
                        "Ed25519Signature2018",
                        "Ed255 19Signature2020",
                        "RsaSignature2018"
                    )
                )
            ),
            jwks = Jwks(
                listOf(
                    Jwk(
                        kty = "OKP",
                        use = "X25519",
                        crv = "enc",
                        x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                        alg = "ECDH-ES",
                        kid = "ed-key1"
                    )
                )
            )
        )

        val clientMetadataJson = Json.encodeToString(ClientMetadataSerializer, clientMetadata)
        val decodedClientMetadata =
            Json.decodeFromString(ClientMetadataSerializer, clientMetadataJson)

        assertThat(decodedClientMetadata)
            .usingRecursiveComparison()
            .isEqualTo(clientMetadata)
    }
}