package io.mosip.openID4VP

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.*
import foundation.identity.jsonld.JsonLDObject
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.test.*

class OpenID4VPTest {

    private lateinit var openID4VP: OpenID4VP
    private val selectedLdpCredentialsList = mapOf(
        "456" to mapOf(
            FormatType.LDP_VC to listOf(ldpCredential1, ldpCredential2)
        ), "789" to mapOf(
            FormatType.LDP_VC to listOf(ldpCredential2)
        )
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(
            FormatType.MSO_MDOC to listOf(mdocCredential)
        )
    )

    @BeforeTest
    fun setUp() {
        mockkObject(NetworkManagerClient)

        openID4VP = OpenID4VP("test-OpenID4VP")
        openID4VP.authorizationRequest = authorizationRequest
        setField(openID4VP, "responseUri", responseUrl)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should authenticate verifier successfully`() {
        mockkObject(AuthorizationRequest.Companion)

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        val result = openID4VP.authenticateVerifier(
            "openid-vc://?request=test-request",
            trustedVerifiers,
            true,
            walletMetadata
        )

        assertEquals(authorizationRequest, result)
        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                "openid-vc://?request=test-request", trustedVerifiers, walletMetadata, any(), true
            )
        }
    }

    @Test
    fun `should throw exception during verifier authentication`() {
        mockkObject(AuthorizationRequest.Companion)
        mockkObject(NetworkManagerClient)

        val testException = InvalidInput("", "Invalid authorization request","")

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any(), any(), any(), any(), any()
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
        every { URDNA2015Canonicalization.canonicalize(any()) } returns "{\"valid\":\"json\"}"
        every { JsonLDObject.fromJson(any<String>()) } returns JsonLDObject()

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build() } returns mapOf(
            "unsignedVPToken" to unsignedLdpVPToken,
            "vpTokenSigningPayload" to vpTokenSigningPayload
        )

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build() } returns mapOf(
            "unsignedVPToken" to unsignedMdocVPToken,
            "vpTokenSigningPayload" to listOf(mdocCredential)
        )

        val actualUnsignedVPTokens = openID4VP.constructUnsignedVPToken(
            selectedLdpCredentialsList + selectedMdocCredentialsList,
            holderId,
            signatureSuite
        )

        val expectedUnsignedVPTokens = unsignedVPTokens
        assertEquals(expectedUnsignedVPTokens[FormatType.LDP_VC]!!["unsignedVPToken"], actualUnsignedVPTokens[FormatType.LDP_VC])
        assertEquals(expectedUnsignedVPTokens[FormatType.MSO_MDOC]!!["unsignedVPToken"], actualUnsignedVPTokens[FormatType.MSO_MDOC])
    }

    @Test
    fun `should throw exception during VP token construction with invalid data`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val testException = InvalidData("Invalid credential format","")

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any(), any())
        } throws testException

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any())
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
                any()
            )
        } returns mapOf("body" to "VP share success")

        openID4VP.sendErrorToVerifier(InvalidData("Unsupported response_mode",""))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == "Unsupported response_mode"
                },
                null
            )
        }
    }


    @Test
    fun `should handle exception during sending error to verifier`() {

        mockkStatic(Logger::class)
        val mockLogger = mockk<Logger>()
        every { Logger.getLogger(any()) } returns mockLogger

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any())
        } throws Exception("Network error")

        val field = openID4VP::class.java.getDeclaredField("responseUri")
        field.isAccessible = true
        field.set(openID4VP, "https://mock-verifier.com/callback")

        var capturedLog: String? = null
        every { mockLogger.log(eq(Level.SEVERE), any<String>()) } answers {
            capturedLog = secondArg()
        }

        openID4VP.sendErrorToVerifier(Exception("Network error"))

        assertTrue(
            capturedLog?.contains("Failed to send error to verifier: Network error") == true
        )

        unmockkStatic(Logger::class)
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
            NetworkManagerClient.sendHTTPRequest(any(), any(), any())
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
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any(), any())
        } returns emptyMap()

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.constructUnsignedVPToken(emptyMap(), holderId, signatureSuite)

        assertTrue(result.isEmpty())
    }
}
