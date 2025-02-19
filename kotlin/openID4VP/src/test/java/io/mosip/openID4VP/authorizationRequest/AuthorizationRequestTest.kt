package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.clientIdAndSchemeOfDid
import io.mosip.openID4VP.testData.clientIdAndSchemeOfPreRegistered
import io.mosip.openID4VP.testData.clientIdAndSchemeOfReDirectUri
import io.mosip.openID4VP.testData.clientMetadata
import io.mosip.openID4VP.testData.createEncodedAuthorizationRequest
import io.mosip.openID4VP.testData.presentationDefinition
import io.mosip.openID4VP.testData.presentationDefinitionUri
import io.mosip.openID4VP.testData.requestUri
import io.mosip.openID4VP.testData.trustedVerifiers
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AuthorizationRequestTest {
    private lateinit var openID4VP: OpenID4VP
    private lateinit var actualException: Exception
    private lateinit var expectedExceptionMessage: String
    private var shouldValidateClient = true
    private lateinit var mockWebServer: MockWebServer

    val requestParams: Map<String, String> = mapOf(
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
        mockWebServer = MockWebServer()
        mockWebServer.start(8080)

        mockkObject(NetworkManagerClient.Companion)
        openID4VP = OpenID4VP("test-OpenID4VP")

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
        mockWebServer.shutdown()
    }

    @Test
    fun `should throw missing input exception if client_id param is missing in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams.minus("client_id") + mapOf(
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.DID)

        expectedExceptionMessage = "Missing Input: client_id param is required"

        actualException =
            assertThrows(AuthorizationRequestExceptions.MissingInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if client_id param is present in Authorization Request but it's value is empty string`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "",
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.DID)

        expectedExceptionMessage = "Invalid Input: client_id value cannot be an empty string, null, or an integer"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if client_id param is present in Authorization Request but it's value is null`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to null,
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.DID)

        expectedExceptionMessage = "Invalid Input: client_id value cannot be an empty string, null, or an integer"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if neither presentation_definition nor presentation_definition_uri param present in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams.minus("presentation_definition")
            .minus("presentation_definition_uri") + mapOf(
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.DID)

        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param must be present"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if both presentation_definition and presentation_definition_uri request params are present in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        val applicableFields = listOf(
            "client_id",
            "client_id_scheme",
            "response_mode",
            "response_uri",
            "presentation_definition",
            "presentation_definition_uri",
            "response_type",
            "nonce",
            "state",
            "client_metadata"
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(
                authorizationRequestParamsMap, false, ClientIdScheme.DID, applicableFields
            )

        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param can be provided but not both"
        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if received client_id is not matching with predefined Verifiers list client_id`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "https://mock-client-id",
            "client_id_scheme" to ClientIdScheme.PRE_REGISTERED.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

        val expectedExceptionMessage =
            "VP sharing failed: Verifier authentication was unsuccessful"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidVerifierClientID::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid limit disclosure exception if limit disclosure is present and not matching with predefined values`() {
        val presentationDefinition =
            """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","constraints":{"fields":[{"path":["$.type"]}], "limit_disclosure": "not preferred"}}]}"""

        val authorizationRequestParamsMap = requestParams+ clientIdAndSchemeOfDid + mapOf(
            "presentation_definition" to presentationDefinition
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.DID)

        val expectedExceptionMessage =
            "Invalid Input: constraints->limit_disclosure value should be either required or preferred"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidLimitDisclosure::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition & all the other fields are present and valid in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should throw error when client_id_scheme is redirect_uri and response_uri is present`() {

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfReDirectUri
        val applicableFields = listOf(
            "client_id",
            "client_id_scheme",
            "redirect_uri",
            "response_uri",
            "presentation_definition",
            "response_type",
            "nonce",
            "state",
            "client_metadata",
            "response_mode"
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI,
                applicableFields
            )

        val expectedExceptionMessage =
            "Response Uri and Response mode should not be present, when client id scheme is Redirect Uri"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error when client_id_scheme is redirect_uri and redirect_uri and client_id is different`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "https://verifier.env1.net",
            "redirect_uri" to "https://verifier.env2.net",
            "client_id_scheme" to "redirect_uri",
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(
                authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI
            )

        val expectedExceptionMessage = "Client id and redirect_uri value should be equal"
        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidVerifierRedirectUri::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition_uri & all the other fields are present and valid in Authorization Request`() {
         every {
            NetworkManagerClient.sendHTTPRequest(
                presentationDefinitionUri,
                HTTP_METHOD.GET
            )
        } returns presentationDefinition

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered

        val applicableFields =  listOf(
            "client_id",
            "client_id_scheme",
            "response_mode",
            "response_uri",
            "presentation_definition_uri",
            "response_type",
            "nonce",
            "state",
            "client_metadata"
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(
                authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED, applicableFields
            )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if all the fields are valid in Authorization Request and clientValidation is not needed`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfReDirectUri
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(
                authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI
            )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers, false)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should throw missing input exception when client_id_scheme is not available in authorization request query parameter`() {
        val authorizationRequestParamsMap = requestParams.minus("client_id_scheme")
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(
                authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI
            )


        val missingInputException =
            assertThrows(AuthorizationRequestExceptions.MissingInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest,
                    trustedVerifiers,
                    true
                )
            }

        assertEquals("Missing Input: client_id_scheme param is required",missingInputException.message)
    }
}

