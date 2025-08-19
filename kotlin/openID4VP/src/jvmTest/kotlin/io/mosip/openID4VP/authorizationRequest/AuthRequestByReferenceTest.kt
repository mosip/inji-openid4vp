package io.mosip.openID4VP.authorizationRequest

import io.mockk.every
import io.mockk.just
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkStatic
import io.mockk.verify
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID_SCHEME
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.DID
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.constants.ContentEncryptionAlgorithm
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.KeyManagementAlgorithm
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.assertDoesNotThrow
import io.mosip.openID4VP.testData.clientIdOfDid
import io.mosip.openID4VP.testData.clientIdOfPreRegistered
import io.mosip.openID4VP.testData.clientIdOfReDirectUriDraft23
import io.mosip.openID4VP.testData.createAuthorizationRequestObject
import io.mosip.openID4VP.testData.createUrlEncodedData
import io.mosip.openID4VP.testData.didResponse
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.requestParams
import io.mosip.openID4VP.testData.requestUrl
import io.mosip.openID4VP.testData.trustedVerifiers
import io.mosip.openID4VP.testData.walletMetadata
import okhttp3.Headers
import kotlin.test.*

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


        val exception = assertFailsWith<InvalidData> {
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
    fun `should return Authorization Request with populated clientIdScheme(pre-registered) field if the verifier is draft 21 compliant`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered + mapOf(
            CLIENT_ID_SCHEME.value to PRE_REGISTERED.value
        )

        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, draftVersion = 21)
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
                shouldValidateClient = true
            )
        }

        assertEquals(PRE_REGISTERED.value, authorizationRequest.clientIdScheme)
    }

}