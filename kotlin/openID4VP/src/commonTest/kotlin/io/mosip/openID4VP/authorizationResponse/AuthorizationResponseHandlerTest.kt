package io.mosip.openID4VP.authorizationResponse

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.testData.*
import java.io.IOException
import kotlin.test.*

class AuthorizationResponseHandlerTest {
    private val ldpVcList1 = listOf(ldpCredential1, ldpCredential2)
    private val ldpVcList2 = listOf(ldpCredential2)
    private val mdocVcList = listOf(mdocCredential)
    private val selectedLdpVcCredentialsList = mapOf(
        "456" to mapOf(FormatType.LDP_VC to ldpVcList1),
        "789" to mapOf(FormatType.LDP_VC to ldpVcList2)
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(FormatType.MSO_MDOC to mdocVcList)
    )
    private val credentialsMap = mapOf(
        "input1" to mapOf(FormatType.LDP_VC to listOf(ldpCredential1)),
        "input2" to mapOf(FormatType.MSO_MDOC to listOf(mdocCredential))
    )

    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler
    private val mockResponseHandler = mockk<ResponseModeBasedHandler>()

    @BeforeTest
    fun setUp() {
        authorizationResponseHandler = AuthorizationResponseHandler()

        mockkConstructor(LdpVPTokenBuilder::class)
        every { anyConstructed<LdpVPTokenBuilder>().build() } returns ldpVPToken

        mockkConstructor(MdocVPTokenBuilder::class)
        every { anyConstructed<MdocVPTokenBuilder>().build() } returns mdocVPToken

        setField(authorizationResponseHandler, "credentialsMap", selectedLdpVcCredentialsList + selectedMdocCredentialsList)
        setField(authorizationResponseHandler, "unsignedVPTokens", unsignedVPTokens)
        

        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        mockkObject(DateUtil)
        every { DateUtil.formattedCurrentDateTime() } returns "2024-02-13T10:00:00Z"

        mockkObject(NetworkManagerClient)

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

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get(any()) } returns mockResponseHandler
        every { mockResponseHandler.sendAuthorizationResponse(any(), any(), any(), any()) } returns "success"
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC and MSO_MDOC formats`() {
        val expectedUnsignedVPToken = mapOf(
            FormatType.LDP_VC to unsignedLdpVPToken,
            FormatType.MSO_MDOC to unsignedMdocVPToken
        )

        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedMdocCredentialsList + selectedLdpVcCredentialsList,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            holderId = holderId,
            signatureSuite = signatureSuite
        )

        assertNotNull(unsignedVPToken)
        assertEquals(2, unsignedVPToken.size)
        assertEquals(expectedUnsignedVPToken[FormatType.LDP_VC], unsignedVPToken[FormatType.LDP_VC])
        assertEquals(expectedUnsignedVPToken[FormatType.MSO_MDOC], unsignedVPToken[FormatType.MSO_MDOC])
    }

    @Test
    fun `should throw error during construction of data for signing when selected Credentials is empty`() {
        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = mapOf(),
                authorizationRequest = authorizationRequest,
                responseUri = "https://mock-verifier.com",
                holderId = holderId,
                signatureSuite = signatureSuite
            )
        }
        assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            exception.message
        )
    }

    @Test
    fun `should throw error when response type is not supported`() {
        val request = authorizationRequest.copy(responseType = "code")
        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = request,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = authorizationRequest.responseUri!!
            )
        }
        assertEquals("Provided response_type - code is not supported", exception.message)
    }

    @Test
    fun `should throw error when a credential format entry is not available in unsignedVPTokens but available in vpTokenSigningResults`() {
        setField(authorizationResponseHandler, "unsignedVPTokens", emptyMap<FormatType, UnsignedVPToken>())

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = authorizationRequest.responseUri!!
            )
        }

        assertEquals(
            "unable to find the related credential format - LDP_VC in the unsignedVPTokens map",
            exception.message
        )
    }

    @Test
    fun `should throw exception when credentials map is empty`() {
        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = emptyMap(),
                holderId = holderId,
                authorizationRequest = authorizationRequest,
                responseUri = responseUrl,
                signatureSuite = signatureSuite
            )
        }

        assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            exception.message
        )
    }

    @Test
    fun `should successfully share VP with valid signing results`() {
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = mapOf(
                FormatType.LDP_VC to ldpVPTokenSigningResult,
                FormatType.MSO_MDOC to mdocVPTokenSigningResult
            ),
            responseUri = responseUrl
        )

        assertEquals("success", result)

        verify {
            ResponseModeBasedHandlerFactory.get("direct_post")
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                url = responseUrl,
                authorizationResponse = any(),
                walletNonce = any()
            )
        }
    }

    @Test
    fun `should throw exception when response type is not supported`() {
        val mockInvalidRequest = mockk<AuthorizationRequest>()
        every { mockInvalidRequest.responseType } returns "code"

        // Populate internal state with valid input first
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = mockInvalidRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals("Provided response_type - code is not supported", exception.message)
    }


    @Test
    fun `should throw exception when unsupported response mode is provided`() {
        val request = authorizationRequest.copy(responseMode = "unsupported_mode")
        every { ResponseModeBasedHandlerFactory.get("unsupported_mode") } throws
                InvalidData("Unsupported response mode: unsupported_mode","")

        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = request,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals("Unsupported response mode: unsupported_mode", exception.message)
    }

    @Test
    fun `should throw exception when unsupported response type is provided`() {
        // Create a mock AuthorizationRequest with an unsupported response type
        val mockRequestWithUnsupportedType = mockk<AuthorizationRequest>()
        every { mockRequestWithUnsupportedType.responseType } returns "invalid_vp_token"

        // Populate internal state with valid request first
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = mockRequestWithUnsupportedType,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals(
            "Provided response_type - invalid_vp_token is not supported",
            exception.message
        )
    }

    @Test
    fun `should throw exception when format in signing results not found in unsigned tokens`() {
        val ldpOnly = mapOf("input1" to mapOf(FormatType.LDP_VC to listOf(ldpCredential1)))
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = ldpOnly,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = mdocvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals(
            "unable to find the related credential format - MSO_MDOC in the unsignedVPTokens map",
            exception.message
        )
    }

    @Test
    fun `should throw exception when network error occurs during response sending`() {
        every {
            mockResponseHandler.sendAuthorizationResponse(any(), any(), any(), any())
        } throws IOException("Network connection failed")

        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val exception = assertFailsWith<IOException> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals("Network connection failed", exception.message)
    }

    @Test
    fun `should ignore empty credential lists for input descriptors`() {
        val input = mapOf(
            "input1" to mapOf(FormatType.LDP_VC to listOf(ldpCredential1)),
            "input2" to mapOf(FormatType.LDP_VC to emptyList())
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = input,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        assertNotNull(result)
        assertEquals(1, result.size)
        assertEquals(unsignedLdpVPToken, result[FormatType.LDP_VC])
    }

    @Test
    fun `constructUnsignedVPTokenV1 should successfully construct unsigned VP token`() {
        val verifiableCredentials = mapOf(
            "input1" to listOf(encodeToJsonString(ldpCredential1, "ldpCredential1", "LDP_VC")),
            "input2" to listOf(encodeToJsonString(ldpCredential2, "ldpCredential2", "LDP_VC"))
        )

        val result = authorizationResponseHandler.constructUnsignedVPTokenV1(
            verifiableCredentials = verifiableCredentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        assertNotNull(result)
        assertTrue(result.contains("verifiableCredential"))
        assertTrue(result.contains("type"))
    }

    @Test
    fun `constructUnsignedVPTokenV1 should throw exception when credentials map is empty`() {
        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructUnsignedVPTokenV1(
                verifiableCredentials = emptyMap(),
                authorizationRequest = authorizationRequest,
                responseUri = responseUrl
            )
        }

        assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            exception.message
        )
    }

    @Test
    fun `shareVPV1 should successfully share VP and return response`() {
        val vpResponseMetadata = VPResponseMetadata(
            publicKey = "did:example:123#key-1",
            jws = jws,
            domain = "example.com",
            signatureAlgorithm = "Ed25519Signature2020"
        )

        val credentials = mapOf(
            "input1" to listOf(encodeToJsonString(ldpCredential1, "ldpCredential1", "LDP_VC")),
            "input2" to listOf(encodeToJsonString(ldpCredential2, "ldpCredential2", "LDP_VC"))
        )

        authorizationResponseHandler.constructUnsignedVPTokenV1(
            verifiableCredentials = credentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        val result = authorizationResponseHandler.shareVPV1(
            vpResponseMetadata = vpResponseMetadata,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        assertEquals("success", result)

        verify {
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                url = responseUrl,
                authorizationResponse = any(),
                walletNonce = any()
            )
        }
    }

    @Test
    fun `shareVPV1 should throw exception when VP response metadata is invalid`() {
        val mockVPResponseMetadata = mockk<VPResponseMetadata>()
        every { mockVPResponseMetadata.publicKey } returns ""
        every { mockVPResponseMetadata.jws } returns jws
        every { mockVPResponseMetadata.validate() } throws InvalidData("Public key cannot be empty","")

        val credentials = mapOf("input1" to listOf(encodeToJsonString(ldpCredential1, "ldpCredential1", "LDP_VC")))

        authorizationResponseHandler.constructUnsignedVPTokenV1(
            verifiableCredentials = credentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVPV1(
                vpResponseMetadata = mockVPResponseMetadata,
                authorizationRequest = authorizationRequest,
                responseUri = responseUrl
            )
        }

        assertEquals("Public key cannot be empty", exception.message)
    }

    @Test
    fun `shareVPV1 should handle network errors during sharing`() {
        val vpResponseMetadata = VPResponseMetadata(
            publicKey = "did:example:123#key-1",
            jws = jws,
            domain = "example.com",
            signatureAlgorithm = "Ed25519Signature2020"
        )

        val credentials = mapOf("input1" to listOf(encodeToJsonString(ldpCredential1, "ldpCredential1", "LDP_VC")))

        authorizationResponseHandler.constructUnsignedVPTokenV1(
            verifiableCredentials = credentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl
        )

        every {
            mockResponseHandler.sendAuthorizationResponse(any(), any(), any(), any())
        } throws IOException("Network connection failed")

        val exception = assertFailsWith<IOException> {
            authorizationResponseHandler.shareVPV1(
                vpResponseMetadata = vpResponseMetadata,
                authorizationRequest = authorizationRequest,
                responseUri = responseUrl
            )
        }

        assertEquals("Network connection failed", exception.message)
    }
}
