package io.mosip.openID4VP.authorizationRequest

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.*
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import io.mosip.openID4VP.testData.*
import okhttp3.Headers
import kotlin.test.*

class AuthorizationRequestObjectObtainedByReferenceTest {
    private lateinit var openID4VP: OpenID4VP

    @BeforeTest
    fun setUp() {
        openID4VP = OpenID4VP("test-OpenID4VP")

        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/verifier/get-presentation-definition",
                HttpMethod.GET
            )
        } returns mapOf("body" to presentationDefinitionString)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                HttpMethod.GET
            )
        } returns mapOf("body" to didResponse)


    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
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

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
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

        val invalidInputException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
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



        val exceptionWhenRequestUriNetworkCallFails = assertFailsWith<Exception> {
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


        val missingInputException = assertFailsWith<OpenID4VPExceptions.MissingInput> {
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
    fun `should throw error if  request_uri is not valid in authorization request`() {
        val authorizationRequestParamsMap =
            requestParams + clientIdOfDid + mapOf(REQUEST_URI.value to "test-data")

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, ClientIdScheme.REDIRECT_URI)


        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals("request_uri data is not valid", exception.message)
    }




    @Test
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

        val actualException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true,
                walletMetadata = null
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


        assertFailsWith<OpenID4VPExceptions.InvalidData> {
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


        assertFailsWith<OpenID4VPExceptions.InvalidData> {
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
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
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

