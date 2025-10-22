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
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import io.mosip.openID4VP.testData.*
import org.junit.Test
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
        } returns NetworkResponse(200, presentationDefinitionString, mapOf())
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                HttpMethod.GET
            )
        } returns NetworkResponse(200, didResponse, mapOf())
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

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DID
        )

        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "LDP_VC" to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA", "ES256")
                )
            ),
            clientIdSchemesSupported = listOf("REDIRECT_URI"),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH_ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )

        val openID4VP = OpenID4VP("test-OpenID4VP", walletMetadata)

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
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
        } returns NetworkResponse(200,
            createAuthorizationRequestObject(DID, authorizationRequestParamsMap).toString(), mapOf("content-type" to listOf("application/json")))

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
            "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
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
                false,
                walletNonce
            )
        }

        assertEquals(
            "Network error while fetching request_uri: VP sharing failed due to connection timeout",
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


        val invalidDataException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                walletMetadata,
                { _: String -> },
                false,
                walletNonce
            )
        }

        assertEquals(
            "unsigned request is not supported for given client_id_scheme - did",
            invalidDataException.message
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

}

