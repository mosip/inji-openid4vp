package io.mosip.openID4VP

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.*
import foundation.identity.jsonld.JsonLDObject
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.constants.FormatType.LDP_VC
import io.mosip.openID4VP.constants.FormatType.MSO_MDOC
import org.junit.jupiter.api.assertThrows
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.test.*

class OpenID4VPTest {

    private lateinit var openID4VP: OpenID4VP
    private val selectedLdpCredentialsList = mapOf(
        "456" to mapOf(
            LDP_VC to listOf(ldpCredential1, ldpCredential2)
        ), "789" to mapOf(
            LDP_VC to listOf(ldpCredential2)
        )
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(
            MSO_MDOC to listOf(mdocCredential)
        )
    )

    @BeforeTest
    fun setUp() {
        mockkObject(NetworkManagerClient)
        openID4VP = OpenID4VP("test-OpenID4VP")
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)
        setField(openID4VP, "walletNonce", "bMHvX1HGhbh8zqlSWf/fuQ==")
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should authenticate verifier successfully`() {
        mockkObject(AuthorizationRequest)

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any(), any(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        val result = openID4VP.authenticateVerifier(
            "openid-vc://?request=test-request",
            trustedVerifiers,
            true
        )

        assertEquals(authorizationRequest, result)
        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                "openid-vc://?request=test-request",
                trustedVerifiers,
                any(),
                any(),
                true,
                any()
            )
        }
    }

    @Test
    fun `should authenticate verifier successfully for pre-registered verifier with client metadata`() {
        mockkObject(AuthorizationRequest)

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any(), any(), any(), any(), any(), any()
            )
        } returns authorizationRequest
        val trustedVerifiers: List<Verifier> = listOf(
            Verifier(
                "mock-client", listOf(
                    "https://mock-verifier.com/response-uri", "https://verifier.env2.com/responseUri"
                ),
                clientMetadata = ClientMetadata(
                    clientName = "mock-client",
                    vpFormats = mapOf("ldp_vc" to mapOf("signing_alg" to listOf("ES256"))),
                )
            ), Verifier(
                "mock-client2", listOf(
                    "https://verifier.env3.com/responseUri", "https://verifier.env2.com/responseUri"
                )
            )
        )

        val result = openID4VP.authenticateVerifier(
            "openid-vc://?request=test-request",
            trustedVerifiers,
            true
        )

        assertEquals(authorizationRequest, result)
        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                "openid-vc://?request=test-request",
                trustedVerifiers,
                any(),
                any(),
                true,
                any()
            )
        }
    }

    @Test
    fun `should throw exception during verifier authentication`() {
        mockkObject(AuthorizationRequest)
        mockkObject(NetworkManagerClient)

        var openID4VP = OpenID4VP("test-OpenID4VP")

        val testException = InvalidInput("", "Invalid authorization request","")

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any(), any(), any(), any(), any(), any()
            )
        } throws testException

        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any()
            )
        } returns mapOf("body" to "Error sent")

        assertFailsWith<InvalidInput> {
            openID4VP.authenticateVerifier("openid-vc://?request=invalid", trustedVerifiers)
        }
    }

    @Test
    fun `should construct unsigned VP token successfully`() {
        mockkObject(UUIDGenerator)
        mockkObject(URDNA2015Canonicalization)
        mockkStatic(JsonLDObject::class)

        every { UUIDGenerator.generateUUID() } returns "test-uuid-123"
        every { URDNA2015Canonicalization.canonicalize(any()) } returns "base64EncodedCanonicalisedData"
        every { JsonLDObject.fromJson(any<String>()) } returns JsonLDObject()

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build(any()) } returns Pair(
            vpTokenSigningPayload,
            unsignedLdpVPToken
        )

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build(any()) } returns Pair(
            null,
            unsignedMdocVPToken
        )

        val actualUnsignedVPTokens = openID4VP.constructUnsignedVPToken(
            selectedLdpCredentialsList + selectedMdocCredentialsList,
            holderId,
            signatureSuite
        )

        val expectedUnsignedVPTokens = unsignedVPTokens
        assertEquals(expectedUnsignedVPTokens[LDP_VC]!!["unsignedVPToken"], actualUnsignedVPTokens[LDP_VC])
        assertEquals(expectedUnsignedVPTokens[MSO_MDOC]!!["unsignedVPToken"], actualUnsignedVPTokens[MSO_MDOC])
    }

    @Test
    fun `should throw exception during VP token construction with invalid data`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val testException = InvalidData("Invalid credential format","")

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any(), any(), any())
        } throws testException

        setField(openID4VP, "authorizationResponseHandler", mockHandler)
        setField(openID4VP, "walletNonce", "bMHvX1HGhbh8zqlSWf/fuQ==")

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns mapOf("body" to "Error sent")

        val thrown = assertFailsWith<InvalidData> {
            openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList, holderId, signatureSuite)
        }
        assertEquals("Invalid credential format", thrown.message)
    }

    @Test
    fun `should send error to verifier successfully`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf(
                    "status" to 200,
                    "headers" to mapOf("Content-Type" to "application/json"),
                    "body" to """{"message":"VP share success"}"""
                )
        setField(openID4VP, "responseUri", "https://mock-verifier.com/response-uri")

        val dispatchResult =
            openID4VP.sendErrorToVerifier(InvalidData("Unsupported response_mode", ""))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == "Unsupported response_mode"
                },
                any()
            )
        }
        assertEquals("NetworkResponse(statusCode=200, body={\"message\":\"VP share success\"}, headers={})",dispatchResult.toString())
    }

    @Test
    fun `should throw exception during sending error to verifier if any error occurs during the process`() {
        mockkStatic(Logger::class)
        val mockLogger = mockk<Logger>()
        every { Logger.getLogger(any()) } returns mockLogger

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } throws Exception("Network error")

        var capturedLog: String? = null
        every { mockLogger.log(eq(Level.SEVERE), any<String>()) } answers {
            capturedLog = secondArg()
        }

        val errorDispatchFailure: ErrorDispatchFailure = assertThrows<ErrorDispatchFailure> {
            openID4VP.sendErrorToVerifier(Exception("Network error"))
        }

        assertTrue(
            capturedLog?.contains("Failed to send error to verifier: Network error") == true
        )

        unmockkStatic(Logger::class)
        assertEquals("Failed to send error to verifier: Failed to send error to verifier: Network error", errorDispatchFailure.message)
    }

    @Test
    fun `should throw exception during sending error to verifier when the response uri is not available`() {
        setField(openID4VP, "responseUri", null)

        val errorDispatchFailure: ErrorDispatchFailure = assertThrows<ErrorDispatchFailure> {
            openID4VP.sendErrorToVerifier(AccessDenied("Access denied by user", "OpenID4VPTest"))
        }

        assertEquals("Failed to send error to verifier: Response URI is not set. Cannot send error to verifier.", errorDispatchFailure.message)
    }

    @Test
    fun `should handle deprecated constructVerifiablePresentationToken method`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()

        every {
            mockHandler.constructUnsignedVPTokenV1(any(), any(), any())
        } returns "Deprecated VP Token"

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.constructVerifiablePresentationToken(mapOf("id1" to listOf("vc1", "vc2")))

        assertEquals("Deprecated VP Token", result)
    }

    @Test
    fun `should handle deprecated shareVerifiablePresentation method`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val vpResponseMetadata = mockk<VPResponseMetadata>()

        every {
            mockHandler.shareVPV1(any(), any(), any())
        } returns "Deprecated VP Sharing Result"

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.shareVerifiablePresentation(vpResponseMetadata)

        assertEquals("Deprecated VP Sharing Result", result)
    }

    @Test
    fun `should handle exception in deprecated constructVerifiablePresentationToken method`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val exception = InvalidData("Invalid VC format","")

        every {
            mockHandler.constructUnsignedVPTokenV1(any(), any(), any())
        } throws exception

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns mapOf("body" to "Error sent")

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val thrown = assertFailsWith<InvalidData> {
            openID4VP.constructVerifiablePresentationToken(mapOf("id1" to listOf("vc1")))
        }
        assertEquals("Invalid VC format", thrown.message)
    }

    @Test
    fun `should handle empty credential list`() {
        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "test-uuid-123"

        val mockHandler = mockk<AuthorizationResponseHandler>()
        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any(), any(), any())
        } returns emptyMap()

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.constructUnsignedVPToken(emptyMap(), holderId, signatureSuite)

        assertTrue(result.isEmpty())
    }

    @Test
    fun `should include state when sending error to verifier`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "Error sent")

        val customAuthorizationRequest = authorizationRequest.copy(state = "test-state")
        setField(openID4VP, "authorizationRequest", customAuthorizationRequest)

        openID4VP.sendErrorToVerifier(InvalidData("With state test", ""))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == "With state test" &&
                            it["state"] == "test-state"
                },
                any()
            )
        }
    }

    @Test
    fun `should not include state when authorization request has empty state`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "Error sent")

        val customAuthorizationRequest = authorizationRequest.copy(state = "")
        setField(openID4VP, "authorizationRequest", customAuthorizationRequest)

        openID4VP.sendErrorToVerifier(InvalidData("empty state test", ""))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == "empty state test" &&
                            !it.containsKey("state")
                },
                any()
            )
        }
    }

    @Test
    fun `should not include state when authorization request has no state`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "Error sent")

        val noStateAuthorizationRequest = authorizationRequest.copy(state = null)
        setField(openID4VP, "authorizationRequest", noStateAuthorizationRequest)

        openID4VP.sendErrorToVerifier(InvalidData("No state test", ""))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == "No state test" &&
                            !it.containsKey("state")
                },
                any()
            )
        }
    }
}
