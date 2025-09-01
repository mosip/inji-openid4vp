package io.mosip.openID4VP.authorizationRequest

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.just
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.verify
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID_SCHEME
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.DID
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.assertDoesNotThrow
import io.mosip.openID4VP.testData.authRequestWithRedirectUriByValue
import io.mosip.openID4VP.testData.clientIdOfDid
import io.mosip.openID4VP.testData.clientIdOfPreRegistered
import io.mosip.openID4VP.testData.clientIdOfReDirectUriDraft23
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.createAuthorizationRequestObject
import io.mosip.openID4VP.testData.createUrlEncodedData
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.requestParams
import io.mosip.openID4VP.testData.requestUrl
import io.mosip.openID4VP.testData.trustedVerifiers
import io.mosip.openID4VP.testData.walletMetadata
import io.mosip.openID4VP.testData.walletNonce
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.Headers
import org.junit.Assert.assertTrue
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AuthRequestByReferenceTest {

    private lateinit var openID4VP: OpenID4VP

    @BeforeTest
    fun setUp() {
        openID4VP = OpenID4VP("test-OpenID4VP")

        mockkStatic("io.mosip.openID4VP.authorizationRequest.AuthorizationRequestUtilsKt")
        every { validateWalletNonce(any(), any()) } just runs

        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/verifier/get-presentation-definition",
                HttpMethod.GET
            )
        } returns mapOf("body" to presentationDefinitionString)


    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
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
    fun `should send wallet metadata to the verifier only when the request_uri_method is post`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            "request_uri_method" to "post"
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

        val openID4VP = OpenID4VP("test-OpenID4VP", walletMetadata)

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.POST,
                any(),
                any()
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


        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals(
            "Authorization Request Object validation failed: Client Id mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
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
                shouldValidateClient = true
            )
        }
    }

    //Client Id scheme - DID
    @Test
    fun `should return Authorization Request with populated clientIdScheme(did) field if the verifier is draft 21 compliant`() {
        val authorizationRequestParamsMap =
            requestParams + clientIdOfDid + mapOf(CLIENT_ID_SCHEME.value to DID.value)
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                DID,
                authorizationRequestParamsMap,
                draftVersion = 21
            )
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                DID,
                draftVersion = 21
            )

        val authorizationRequest = assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        assertEquals(DID.value, authorizationRequest.clientIdScheme)
    }


    @Test
    fun `should validate request_uri response with valid JWS and correct content type for DID scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val validJwt = createAuthorizationRequestObject(
            clientIdScheme = DID,
            authorizationRequestParamsMap,
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.GET)
        } returns mapOf(
            "header" to Headers.Builder()
                .add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to validJwt
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
    }


    @Test

    fun `should throw exception when content-type is invalid in request_uri response`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val validJwt = createAuthorizationRequestObject(
            clientIdScheme = DID,
            authorizationRequestParamsMap
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.GET)
        } returns mapOf(
            "header" to Headers.Builder()
                .add("content-type", "application/json")
                .build(),
            "body" to validJwt
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals(
            "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
            exception.message
        )
    }

    @Test
    fun `should throw exception when Authorization Request Object is not a signed JWT`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val unsignedJwt = "not.a.valid.jwt"

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.GET)
        } returns mapOf(
            "header" to Headers.Builder()
                .add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to unsignedJwt
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals(
            "Authorization Request Object must be a signed JWT",
            exception.message
        )
    }

    @Test
    fun `should throw exception when JWS signature verification fails`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val invalidSignedJwt = createAuthorizationRequestObject(
            clientIdScheme = DID,
            authorizationRequestParamsMap
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.GET)
        } returns mapOf(
            "header" to Headers.Builder()
                .add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to invalidSignedJwt
        )


        mockkObject(JWSHandler)
        every {
            JWSHandler.verify(any(), any())
        } throws RuntimeException("Invalid signature")

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertTrue(exception.message.contains("JWS signature verification failed"))
    }

    //
    @Test
    fun `should throw exception when request_uri response is empty`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.GET)
        } returns emptyMap()

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        print(exception.message)
        assertEquals(
            "Missing Input: request_uri param is required",
            exception.message
        )
    }

    @Test
    fun `should throw exception when signing algorithm is not supported`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val jwtWithUnsupportedAlg = createAuthorizationRequestObject(
            clientIdScheme = DID,
            authorizationRequestParamsMap,
            jwtHeader = buildJsonObject {
                put("alg", "HS256")
                put("typ", "oauth-authz-req+jwt")
            }
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.GET)
        } returns mapOf(
            "header" to Headers.Builder()
                .add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to jwtWithUnsupportedAlg
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val exception = assertFailsWith<OpenID4VPExceptions.VerificationFailure> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals(
            "Request URI response validation failed No enum constant io.mosip.openID4VP.constants.RequestSigningAlgorithm.HS256",
            exception.message
        )
    }


    @Test
    fun `should return Authorization Request with populated clientIdScheme(pre-registered) field if the verifier is draft 21 compliant`() {
        val trustedVerifiers: List<Verifier> = listOf(
            Verifier(
                "mock-client", listOf(
                    "https://mock-verifier.com/response-uri",
                    "https://verifier.env2.com/responseUri"
                ),
                clientMetadata = deserializeAndValidate(
                    clientMetadataString,
                    ClientMetadataSerializer
                )
            ), Verifier(
                "mock-client2", listOf(
                    "https://verifier.env3.com/responseUri", "https://verifier.env2.com/responseUri"
                )
            )
        )
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered + mapOf(
            CLIENT_ID_SCHEME.value to PRE_REGISTERED.value
        )

        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap,
                draftVersion = 21,
                jwtHeader = buildJsonObject {
                    put("typ", "oauth-authz-req+jwt")
                    put("alg", "EdDSA")
                },
                isPresentationDefinitionUriPresent = true

            )
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            PRE_REGISTERED,
            draftVersion = 21
        )


        val authorizationRequest = assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true,
            )
        }

        assertEquals(PRE_REGISTERED.value, authorizationRequest.clientIdScheme)
    }


    @Test
    fun `should throw exception when body is missing in request_uri response`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.GET)
        } returns mapOf(
            "header" to Headers.Builder()
                .add("content-type", "application/oauth-authz-req+jwt")
                .build()
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, DID)

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals("Missing body in request_uri response", exception.message)
    }

    @Test
    fun `should throw exception when wallet_nonce validation fails in POST flow`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "post"
        )

        val jwt = createAuthorizationRequestObject(DID, authorizationRequestParamsMap)

        mockkStatic("io.mosip.openID4VP.authorizationRequest.AuthorizationRequestUtilsKt")
        every {
            validateWalletNonce(
                any(),
                any()
            )
        } throws IllegalArgumentException("wallet_nonce mismatch")

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns mapOf(
            "header" to Headers.Builder()
                .add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to jwt
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val exception = assertFailsWith<InvalidData> {
            OpenID4VP("test", walletMetadata).authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertTrue(exception.message.contains("Wallet nonce validation failed"))
    }

    @Test
    fun `should throw exception when alg is missing in JWS header`() {
        val requestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val jwsWithoutAlg = createAuthorizationRequestObject(
            clientIdScheme = DID,
            requestParamsMap,
            jwtHeader = buildJsonObject { put("typ", "oauth-authz-req+jwt") }
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.GET)
        } returns mapOf(
            "header" to Headers.Builder()
                .add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to jwsWithoutAlg
        )

        val encoded = createUrlEncodedData(requestParamsMap, true, DID)

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(encoded, trustedVerifiers, true)
        }

        assertEquals(
            "Request URI response validation failed - 'alg' is not present in JWS header",
            exception.message
        )
    }

//MARK: Pre-registered

    //Client Id scheme - Pre-registered
    @Test
    fun `should return back authorization request successfully when authorization request is obtained by reference in pre-registered client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.GET,
                any(),
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap,
                jwtHeader = jwtHeader,
                isPresentationDefinitionUriPresent = true
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
                true,
                walletNonce
            )
        }
    }

    //Client Id - Pre-registered
    @Test
    fun `should validate client_id when authorization request is obtained by reference in pre-registered client id scheme`() {
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, any())
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED, requestParams + mapOf(
                    CLIENT_ID.value to "wrong-client-id",
                    CLIENT_ID_SCHEME.value to PRE_REGISTERED.value,
                ),

                jwtHeader = jwtHeader
            )
        )

        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)

        val invalidClientIdException =
            assertFailsWith<InvalidData> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest,
                    trustedVerifiers,
                    shouldValidateClient = true
                )
            }

        assertEquals(
            "Authorization Request Object validation failed: Client Id mismatch in Authorization Request parameter and the Request Object",
            invalidClientIdException.message
        )
    }

    //Client Id - Pre-registered
    @Test
    fun `should succeed when alg is supported in wallet metadata`() {

        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered +
                mapOf(AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "post")
        openID4VP = OpenID4VP("test-OpenID4VP", walletMetadata)
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED, authorizationRequestParamsMap,
                jwtHeader = jwtHeader,
                isPresentationDefinitionUriPresent = true
            )
        )

        val encoded = createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)

        openID4VP.authenticateVerifier(encoded, trustedVerifiers, true)
    }

    @Test
    fun `should throw when alg is not-supported in wallet metadata`() {

        openID4VP = OpenID4VP("test-OpenID4VP", walletMetadata)
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "ES256")
        }
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED, requestParams + clientIdOfPreRegistered + mapOf(
                    "request_uri_method" to "post"
                ),

                jwtHeader = jwtHeader
            )
        )

        val encoded = createUrlEncodedData(
            requestParams + clientIdOfPreRegistered + mapOf(
                "request_uri_method" to "post"
            ), true, PRE_REGISTERED
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(encoded, trustedVerifiers, true)
        }

        assertEquals(
            "Request URI response validation failed - request_object_signing_alg is not supported by wallet",
            exception.message
        )

    }

    @Test
    fun `should throw when client_id is missing in authorization request parameters`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "post"
        )

        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap,
                jwtHeader = jwtHeader,

                )
        )

        val encoded = createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            openID4VP.authenticateVerifier(encoded, trustedVerifiers, shouldValidateClient = true)
        }

        assertEquals(
            "Missing Input: client_id param is required",
            exception.message
        )
    }

    @Test
    fun `should throw when client_id is missing inside JWT claims`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered +
                mapOf(AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "post")

        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt")
                .build(),
            "body" to createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap,
                jwtHeader = jwtHeader,

                removeClientId = true
            )
        )

        val encoded = createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(encoded, trustedVerifiers, shouldValidateClient = true)
        }

        assertEquals(
            "Authorization Request Object validation failed: Client Id mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
    }


    //Client Id scheme - Redirect URI
    @Test
    fun `should accept valid inline request with EdDSA for redirect_uri scheme`() {
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }

        val jwtRequest = createAuthorizationRequestObject(
            clientIdScheme = ClientIdScheme.REDIRECT_URI,
            authorizationRequestParams = requestParams + clientIdOfReDirectUriDraft23,
            jwtHeader = jwtHeader,
        ) as String

        val encoded = createUrlEncodedData(
            requestParams + clientIdOfReDirectUriDraft23 + mapOf("request" to jwtRequest),
            clientIdScheme = ClientIdScheme.REDIRECT_URI
        )

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(encoded, trustedVerifiers, shouldValidateClient = true)
        }
    }

    @Test
    fun `should fail if request_uri is used with redirect_uri scheme`() {
        val encoded = createUrlEncodedData(
            requestParams + clientIdOfReDirectUriDraft23,
            clientIdScheme = ClientIdScheme.REDIRECT_URI,
            applicableFields = authRequestWithRedirectUriByValue + listOf("request_uri")
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(encoded, trustedVerifiers, shouldValidateClient = true)
        }

        assertEquals(
            "request_uri is not supported for given client_id_scheme - redirect_uri",
            exception.message
        )
    }


}