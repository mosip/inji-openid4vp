package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import io.mosip.openID4VP.testData.clientIdAndSchemeOfDid
import io.mosip.openID4VP.testData.clientIdAndSchemeOfPreRegistered
import io.mosip.openID4VP.testData.clientMetadata
import io.mosip.openID4VP.testData.createAuthorizationRequestObject
import io.mosip.openID4VP.testData.createEncodedAuthorizationRequest
import io.mosip.openID4VP.testData.didResponse
import io.mosip.openID4VP.testData.presentationDefinition
import io.mosip.openID4VP.testData.presentationDefinitionUri
import io.mosip.openID4VP.testData.requestUri
import io.mosip.openID4VP.testData.trustedVerifiers
import io.mosip.openID4VP.testData.walletMetadata
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertDoesNotThrow
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class AuthorizationRequestObjectObtainedByReference {
    private lateinit var openID4VP: OpenID4VP

    private val requestParams: Map<String, String> = mapOf(
        "client_id" to "https://mock-verifier.com",
        "client_id_scheme" to "pre-registered",
        "redirect_uri" to "https://mock-verifier.com",
        "response_uri" to "https://verifier.env1.net/responseUri",
        "request_uri" to requestUri,
        "request_uri_method" to "get",
        "presentation_definition" to presentationDefinition,
        "presentation_definition_uri" to presentationDefinitionUri,
        "response_type" to "vp_token",
        "response_mode" to "direct_post",
        "nonce" to "VbRRB/LTxLiXmVNZuyMO8A==",
        "state" to "+mRQe1d6pBoJqF6Ab28klg==",
        "client_metadata" to clientMetadata
    )

    @Before
    fun setUp() {
        openID4VP = OpenID4VP("test-OpenID4VP")

        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                presentationDefinitionUri,
                HTTP_METHOD.GET
            )
        } returns presentationDefinition
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                HTTP_METHOD.GET
            )
        } returns didResponse

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
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    //Client Id scheme - DID
    @Test
    fun `should return Authorization Request if it has request uri and it is a valid authorization request in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)

        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(
                authorizationRequestParamsMap,
                true,
                ClientIdScheme.DID
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
    fun `should throw exception when the call to request_uri method fails in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                HTTP_METHOD.GET
            )
        } throws NetworkManagerClientExceptions.NetworkRequestTimeout()

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        val exceptionWhenRequestUriNetworkCallFails = assertThrows(Exception::class.java) {
            AuthorizationRequest.validateAndGetAuthorizationRequest(
                encodedAuthorizationRequest,
                { _: String -> },
                trustedVerifiers,
                false,
                ""
            )
        }

        assertEquals(
            "VP sharing failed due to connection timeout",
            exceptionWhenRequestUriNetworkCallFails.message
        )
    }

    @Test
    fun `should make call to request_uri with the request_uri_method when the fields are available in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)

        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true, ClientIdScheme.REDIRECT_URI )


        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                HTTP_METHOD.GET
            )
        }
    }

    @Test
    fun `should make a call to request_uri in get http call if request_uri_method is not available in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams.minus("request_uri_method") + clientIdAndSchemeOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)

        val encodedAuthorizationRequest = createEncodedAuthorizationRequest(
            authorizationRequestParamsMap,
            true,
            ClientIdScheme.DID
        )

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                HTTP_METHOD.GET
            )
        }
    }

    @Test
    fun `should throw exception when the client_id validation fails while obtaining Authorization request object by reference in did client id scheme`() {
       every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, requestParams + mapOf(
            "client_id" to "wrong-client-id",
            "client_id_scheme" to ClientIdScheme.DID.value
        ))

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        val exception = assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
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
    fun `should throw exception when the client_id_scheme validation fails while obtaining Authorization request object by reference in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.PRE_REGISTERED.value
        ))

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)

        val exception = assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals(
            "Client Id scheme mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
    }

    //Client Id scheme - Pre-registered
    @Test
    fun `should return back authorization request successfully when authorization request is obtained by reference in pre-registered client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                HTTP_METHOD.GET
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.PRE_REGISTERED, authorizationRequestParamsMap)

        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        assertDoesNotThrow {
            AuthorizationRequest.validateAndGetAuthorizationRequest(
                encodedAuthorizationRequest,
                { _: String -> },
                trustedVerifiers,
                false,
                null
            )
        }
    }

    //Client Id - Pre-registered
    @Test
    fun `should validate client_id when authorization request is obtained by reference in pre-registered client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, requestParams + mapOf(
            "client_id" to "wrong-client-id",
            "client_id_scheme" to ClientIdScheme.PRE_REGISTERED.value
        ))

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)

        val invalidClientIdException =
            assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
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

    //Client Id scheme - Pre-registered
    @Test
    fun `should validate client_id_scheme when authorization request is obtained by reference in pre-registered client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, requestParams + mapOf(
            "client_id" to "https://verifier.env1.net",
            "client_id_scheme" to ClientIdScheme.DID.value
        ))

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)

        val invalidClientIsSchemeException =
            assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest,
                    trustedVerifiers,
                    shouldValidateClient = true
                )
            }

        assertEquals(
            "Client Id scheme mismatch in Authorization Request parameter and the Request Object",
            invalidClientIsSchemeException.message
        )
    }

    @Test
    fun `should send wallet metadata to the verifier when the request_uri_method is post`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid + mapOf(
            "request_uri_method" to "post"
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)
        val walletMetadataMap = mapOf(
            "wallet_metadata" to URLEncoder.encode(
                walletMetadata,
                StandardCharsets.UTF_8.toString()
            )
        )
        println(walletMetadataMap)
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                HTTP_METHOD.POST,
                walletMetadataMap,
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true,
            walletMetadata
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUri,
                HTTP_METHOD.POST,
                walletMetadataMap,
                any()
            )
        }
    }

    @Test
    fun `should throw error if vp_formats_supported is not present in wallet metadata`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid + mapOf(
            "request_uri_method" to "post"
        )
        val walletMetadata = """
            {
              "presentation_definition_uri_supported": true,
              "client_id_schemes_supported": [
                "redirect_uri"
              ]
            }
            """.trimIndent()

        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(
                authorizationRequestParamsMap,
                true,
                ClientIdScheme.DID
            )

        val missingInputException =
            assertThrows(AuthorizationRequestExceptions.MissingInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest,
                    trustedVerifiers,
                    shouldValidateClient = true,
                    walletMetadata
                )
            }

        assertEquals(
            "Missing Input: wallet_metadata->vp_formats_supported param is required",
            missingInputException.message
        )
    }

}

