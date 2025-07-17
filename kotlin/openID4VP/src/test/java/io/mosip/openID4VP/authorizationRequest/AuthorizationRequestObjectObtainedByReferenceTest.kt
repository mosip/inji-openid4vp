package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.*
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.Exceptions.InvalidData
import io.mosip.openID4VP.exceptions.Exceptions.MissingInput
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import io.mosip.openID4VP.testData.*
import io.mosip.vercred.vcverifier.DidWebResolver
import okhttp3.Headers
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows

class AuthorizationRequestObjectObtainedByReferenceTest {
    private lateinit var openID4VP: OpenID4VP

    @Before
    fun setUp() {
        openID4VP = OpenID4VP("test-OpenID4VP")

        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/verifier/get-presentation-definition",
                HttpMethod.GET
            )
        } returns mapOf("body" to presentationDefinitionString)

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

        mockkConstructor(DidWebResolver::class)
        every { anyConstructed<DidWebResolver>().resolve() } returns convertJsonToMap(didResponse)
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should send wallet metadata to the verifier only when the request_uri_method is post`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            "request_uri_method" to "post"
        )
        val requestBody = mapOf(
            "wallet_metadata" to
                    encodeToJsonString(
                        walletMetadata,
                        "wallet_metadata",
                        "AuthorizationRequestObjectObtainedByReferenceTest"
                    )
        )

        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.POST,
                requestBody,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(DID, authorizationRequestParamsMap)
        )


        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true,
            walletMetadata
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.POST,
                requestBody,
                any()
            )
        }
    }

    @Test
    fun `should validate and throw error if the client id scheme is not supported by wallet when the request_uri_method is post`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            "request_uri_method" to "post"
        )
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("RSA")
                )
            ),
            clientIdSchemesSupported = listOf(
                ClientIdScheme.REDIRECT_URI.value,
                PRE_REGISTERED.value
            ),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val exception = assertThrows<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true,
                walletMetadata
            )
        }
        assertEquals("client_id_scheme is not support by wallet", exception.message)
    }

    @Test
    fun `should validate and throw error if the signing algorithm is not supported by wallet when the request_uri_method is post`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            "request_uri_method" to "post"
        )
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("RSA")
                )
            ),
            clientIdSchemesSupported = listOf(DID.value, PRE_REGISTERED.value),
            requestObjectSigningAlgValuesSupported = listOf("RSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(DID, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val exception = assertThrows<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true,
                walletMetadata
            )
        }
        assertEquals("request_object_signing_alg is not support by wallet", exception.message)
    }

    @Test
    fun `should validate and throw error if the signing algorithm supported  by wallet is empty or null when the client id scheme is did and request uri method is post`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            "request_uri_method" to "post"
        )
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("RSA")
                )
            ),
            clientIdSchemesSupported = listOf(DID.value, PRE_REGISTERED.value),
            requestObjectSigningAlgValuesSupported = null,
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(DID, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val exception = assertThrows<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true,
                walletMetadata
            )
        }
        assertEquals("request_object_signing_alg_values_supported is not present in wallet metadata", exception.message)
    }

    //Client Id scheme - DID
    @Test
    fun `should return Authorization Request if it has request uri and it is a valid authorization request in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(DID, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                DID
            )

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true,
                null
            )
        }
    }

    //Client Id scheme - DID
    @Test
    fun `should return Authorization Request with populated clientIdScheme(did) field if the verifier is draft 21 compliant`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(CLIENT_ID_SCHEME.value to DID.value)
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(DID, authorizationRequestParamsMap, draftVersion = 21)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                DID,
                draftVersion = 21
            )

        val authorizationRequest  = assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true,
                null
            )
        }
        assertEquals(DID.value, authorizationRequest.clientIdScheme)
    }

    @Test
    fun `should return Authorization Request with populated clientIdScheme(pre-registered) field if the verifier is draft 21 compliant`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered + mapOf(CLIENT_ID_SCHEME.value to PRE_REGISTERED.value)
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json")
                .build(),
            "body" to createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, draftVersion = 21)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                PRE_REGISTERED,
                draftVersion = 21
            )

        val authorizationRequest  = assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true,
                null
            )
        }
        assertEquals(PRE_REGISTERED.value, authorizationRequest.clientIdScheme)
    }

    @Test
    fun `should throw error if context type is wrong for request uri response`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(DID, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                DID
            )

        val invalidInputException = assertThrows<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        assertEquals(
            "Authorization Request must be signed for given client_id_scheme",
            invalidInputException.message
        )
    }

    @Test
    fun `should throw exception when the call to request_uri method fails in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.GET
            )
        } throws NetworkManagerClientExceptions.NetworkRequestTimeout()

        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, DID)


        val exceptionWhenRequestUriNetworkCallFails = assertThrows(Exception::class.java) {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                walletMetadata,
                { _: String -> },
                false
            )
        }

        assertEquals(
            "VP sharing failed due to connection timeout",
            exceptionWhenRequestUriNetworkCallFails.message
        )
    }

    @Test
    fun `should throw exception when request_uri is not present in did client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                false,
                DID,
                authRequestWithDidByValue
            )


        val missingInputException = assertThrows(MissingInput::class.java) {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                walletMetadata,
                { _: String -> },
                false
            )
        }

        assertEquals(
            "Missing Input: request_uri param is required",
            missingInputException.message
        )
    }

    @Test
    fun `should make call to request_uri with the request_uri_method when the fields are available in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(DID, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, ClientIdScheme.REDIRECT_URI)


        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.GET
            )
        }
    }

    @Test
    fun `should throw error if  request_uri is not valid in authorization request`() {
        val authorizationRequestParamsMap =
            requestParams + clientIdOfDid + mapOf(REQUEST_URI.value to "test-data")

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, ClientIdScheme.REDIRECT_URI)


        val exception = assertThrows<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals("request_uri data is not valid", exception.message)
    }

    @Test
    fun `should make a call to request_uri in get http call if request_uri_method is not available in did client id scheme`() {
        val authorizationRequestParamsMap =
            requestParams.minus("request_uri_method") + clientIdOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(DID, authorizationRequestParamsMap)
        )
        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.GET
            )
        }

    }

    @Test
    fun `should return authorization request from redirect uri scheme where request uri is present`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft23
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(
                ClientIdScheme.REDIRECT_URI,
                authorizationRequestParamsMap
            )
        )
        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            ClientIdScheme.REDIRECT_URI
        )

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.GET
            )
        }

    }

    @Test
    fun `should throw exception when the client_id validation fails while obtaining Authorization request object by reference in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, any())
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                DID, requestParams + mapOf(
                    CLIENT_ID.value to "wrong-client-id",
                    CLIENT_ID_SCHEME.value to DID.value
                )
            )
        )

        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, DID)


        val exception = assertThrows(InvalidData::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
    }@Test

    fun `should throw exception when the client_id_scheme validation fails while obtaining Authorization request object by reference in redirect_uri client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft21 + mapOf(CLIENT_ID_SCHEME.value to PRE_REGISTERED.value)
        val applicableFields = listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            PRESENTATION_DEFINITION.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value,
            RESPONSE_URI.value,
            RESPONSE_MODE.value
        )
        val expectedExceptionMessage = "Client Id Scheme mismatch in Authorization Request parameter and the Request Object"

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap +  mapOf(CLIENT_ID_SCHEME.value to ClientIdScheme.REDIRECT_URI.value),
            true,
            PRE_REGISTERED,
            applicableFields,
            draftVersion = 21
        )

        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json")
                .build(),
            "body" to createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, draftVersion = 21)
        )

        val actualException =
            assertThrows(InvalidData::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, true, null
                )
            }
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    //Client Id scheme - Pre-registered
    @Test
    fun `should return back authorization request successfully when authorization request is obtained by reference in pre-registered client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.GET,
                any(),
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap
            )
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)


        assertDoesNotThrow {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                walletMetadata,
                { _: String -> },
                false
            )
        }
    }

    @Test
    fun `should throw error when signed authorization request is obtained by reference in pre-registered client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.GET
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap
            )
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, DID)


        assertThrows<InvalidData> {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                walletMetadata,
                { _: String -> },
                false
            )
        }
    }

    @Test
    fun `should throw error when signed authorization request is obtained by reference in redirect client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft23
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.GET
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                ClientIdScheme.REDIRECT_URI,
                authorizationRequestParamsMap
            )
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, DID)


        assertThrows<InvalidData> {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                walletMetadata,
                { _: String -> },
                false
            )
        }
    }

    //Client Id - Pre-registered
    @Test
    fun `should validate client_id when authorization request is obtained by reference in pre-registered client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, any())
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED, requestParams + mapOf(
                    CLIENT_ID.value to "wrong-client-id",
                    CLIENT_ID_SCHEME.value to PRE_REGISTERED.value
                )
            )
        )

        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)

        val invalidClientIdException =
            assertThrows<InvalidData> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest,
                    trustedVerifiers,
                    shouldValidateClient = true
                )
            }

        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            invalidClientIdException.message
        )
    }
}

