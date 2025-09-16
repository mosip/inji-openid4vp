package io.mosip.openID4VP.authorizationResponse

import foundation.identity.jsonld.JsonLDObject
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.mapping.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt.SdJwtVPTokenSigningResult
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.FormatType.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.testData.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Test
import java.io.IOException
import kotlin.collections.mapOf
import kotlin.test.*

class AuthorizationResponseHandlerTest {
    private val ldpVcList1 = listOf(ldpCredential1, ldpCredential2)
    private val ldpVcList2 = listOf(ldpCredential2)
    private val mdocVcList = listOf(mdocCredential)

    private val selectedLdpVcCredentialsList = mapOf(
        "456" to mapOf(LDP_VC to ldpVcList1),
        "789" to mapOf(LDP_VC to ldpVcList2)
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(MSO_MDOC to mdocVcList)
    )

    private val selectedSdJwtCredentialsList = mapOf(
        "142" to mapOf(VC_SD_JWT to listOf(sdJwtCredential1))
    )
    private val credentialsMap = mapOf(
        "input1" to mapOf(LDP_VC to listOf(ldpCredential1)),
        "input2" to mapOf(MSO_MDOC to listOf(mdocCredential))
    )

    private val credentialMap2 = mapOf(
        "input1" to mapOf(LDP_VC to listOf(ldpCredential1, ldpCredential2)),
        "input2" to mapOf(MSO_MDOC to listOf(mdocCredential)),
        "input3" to mapOf(VC_SD_JWT to listOf(sdJwtCredential1, sdJwtCredential2))
    )

    private val unsignedKBJwt = "eyJhbGciOiJFUzI1NksifQ.eyJub25jZSI6Im5vbmNlIn0"
    private val kbJwtSignature = "dummy_signature"

    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler
    private val mockResponseHandler = mockk<ResponseModeBasedHandler>()

    @BeforeTest
    fun setUp() {
        authorizationResponseHandler = AuthorizationResponseHandler()

        mockkConstructor(LdpVPTokenBuilder::class)
        every { anyConstructed<LdpVPTokenBuilder>().build(any(), any(), any(), any()) } returns Triple(
            listOf(ldpVPToken), listOf(
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", "$.verifiableCredential[0]")
                ),
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", "$.verifiableCredential[1]")
                )
            ),
                2
        )

        mockkConstructor(MdocVPTokenBuilder::class)
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(mdocVPToken), listOf(), 0
        )

        setField(
            authorizationResponseHandler,
            "formatToCredentialInputDescriptorMapping",
            mapOf(
                LDP_VC to listOf(
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential1, "456"),
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential2, "789"),
                )
            ) + mapOf(
                MSO_MDOC to listOf(
                    CredentialInputDescriptorMapping(
                        MSO_MDOC,
                        mdocVcList.first(),
                        "123"
                    )
                )
            )
        )
        setField(
            authorizationResponseHandler, "unsignedVPTokenResults", mapOf(
                LDP_VC to Pair(vpTokenSigningPayload, unsignedLdpVPToken),
                MSO_MDOC to Pair(null, unsignedMdocVPToken),
            )
        )
        setField(authorizationResponseHandler, "walletNonce", "bMHvX1HGhbh8zqlSWf/fuQ==")


        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        mockkObject(URDNA2015Canonicalization)
        mockkStatic(JsonLDObject::class)

        every { URDNA2015Canonicalization.canonicalize(any()) } returns "base64EncodedCanonicalisedData"
        every { JsonLDObject.fromJson(any<String>()) } returns JsonLDObject()

        mockkObject(DateUtil)
        every { DateUtil.formattedCurrentDateTime() } returns "2024-02-13T10:00:00Z"

        mockkObject(NetworkManagerClient)

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build(any()) } returns Pair(
            vpTokenSigningPayload, unsignedLdpVPToken
        )

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build(any()) } returns Pair(
            null,
            unsignedMdocVPToken,
        )

        mockkConstructor(UnsignedSdJwtVPTokenBuilder::class)
        every { anyConstructed<UnsignedSdJwtVPTokenBuilder>().build(any()) } returns Pair(
            null,
            unsignedSdJwtVPToken,
        )
        every { anyConstructed<UnsignedSdJwtVPTokenBuilder>().build(any()) } returns Pair(
            null,
            unsignedSdJwtVPToken,
        )

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get(any()) } returns mockResponseHandler
        every {
            mockResponseHandler.sendAuthorizationResponse(
                any(),
                any(),
                any(),
                any()
            )
        } returns "success"
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC and MSO_MDOC formats`() {
        val expectedUnsignedVPToken = mapOf(
            LDP_VC to unsignedLdpVPToken,
            MSO_MDOC to unsignedMdocVPToken,
        )

        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedMdocCredentialsList + selectedLdpVcCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        assertNotNull(unsignedVPToken)
        assertEquals(2, unsignedVPToken.size)
        assertEquals(expectedUnsignedVPToken[LDP_VC], unsignedVPToken[LDP_VC])
        assertEquals(
            expectedUnsignedVPToken[MSO_MDOC],
            unsignedVPToken[MSO_MDOC]
        )
    }

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC, MSO_MDOC, SD_JWT formats`() {

        val expectedUnsignedVPToken = mapOf(
            LDP_VC to unsignedLdpVPToken,
            MSO_MDOC to unsignedMdocVPToken,
            VC_SD_JWT to unsignedSdJwtVPToken
        )
        authorizationRequest.presentationDefinition = deserializeAndValidate(
            presentationDefinitionMapWithSdJwt,
            PresentationDefinitionSerializer
        )
        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = selectedMdocCredentialsList + selectedLdpVcCredentialsList + selectedSdJwtCredentialsList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        assertNotNull(unsignedVPToken)
        assertEquals(3, unsignedVPToken.size)
        assertEquals(expectedUnsignedVPToken[LDP_VC], unsignedVPToken[LDP_VC])
        assertEquals(expectedUnsignedVPToken[VC_SD_JWT], unsignedVPToken[VC_SD_JWT])
        assertEquals(
            expectedUnsignedVPToken[MSO_MDOC],
            unsignedVPToken[MSO_MDOC]
        )
    }

    @Test
    fun `should throw error during construction of data for signing when selected Credentials is empty`() {
        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = mapOf(),
                holderId = holderId,
                authorizationRequest = authorizationRequest,
                responseUri = "https://mock-verifier.com",
                signatureSuite = signatureSuite,
                nonce = walletNonce
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
        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            emptyMap<FormatType, Pair<Any?, UnsignedVPToken>>()
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = authorizationRequest.responseUri!!
            )
        }

        assertEquals(
            "VPTokenSigningResult not provided for the required formats",
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
                signatureSuite = signatureSuite,
                nonce = walletNonce
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
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = mapOf(
                LDP_VC to ldpVPTokenSigningResult,
                MSO_MDOC to mdocVPTokenSigningResult
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
            signatureSuite = signatureSuite,
            nonce = walletNonce
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
                InvalidData("Unsupported response mode: unsupported_mode", "")

        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = request,
                vpTokenSigningResults = ldpvpTokenSigningResults + mdocvpTokenSigningResults,
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
            signatureSuite = signatureSuite,
            nonce = walletNonce
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
        val ldpOnly = mapOf("input1" to mapOf(LDP_VC to listOf(ldpCredential1)))
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = ldpOnly,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val exception = assertFailsWith<InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = mdocvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals(
            "VPTokenSigningResult not provided for the required formats",
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
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        val exception = assertFailsWith<IOException> {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults + mdocvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        assertEquals("Network connection failed", exception.message)
    }

    @Test
    fun `should ignore empty credential lists for input descriptors`() {
        val input = mapOf(
            "input1" to mapOf(LDP_VC to listOf(ldpCredential1)),
            "input2" to mapOf(LDP_VC to emptyList())
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = input,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertEquals(1, result.size)
        assertEquals(unsignedLdpVPToken, result[LDP_VC])
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
        every { mockVPResponseMetadata.validate() } throws InvalidData(
            "Public key cannot be empty",
            ""
        )

        val credentials = mapOf(
            "input1" to listOf(
                encodeToJsonString(
                    ldpCredential1,
                    "ldpCredential1",
                    "LDP_VC"
                )
            )
        )

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

        val credentials = mapOf(
            "input1" to listOf(
                encodeToJsonString(
                    ldpCredential1,
                    "ldpCredential1",
                    "LDP_VC"
                )
            )
        )

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


    @Test
    fun ` wallet nonce is different for every construct unsignedVPToken call`() {
        val verifiableCredentials = mapOf(
            "input_descriptor1" to mapOf(
                LDP_VC to listOf(ldpCredential1)
            )
        )
        // First call
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = verifiableCredentials,
            holderId = "holder-id",
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = "JsonWebSignature2020",
            nonce = walletNonce
        )

        // Get the nonce from the first call using reflection
        val walletNonceField =
            AuthorizationResponseHandler::class.java.getDeclaredField("walletNonce")
        walletNonceField.isAccessible = true
        val firstNonce = walletNonceField.get(authorizationResponseHandler) as String

        // Second call
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = verifiableCredentials,
            holderId = "holder- id",
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = "JsonWebSignature2020",
            nonce = walletNonce
        )

        val secondNonce = walletNonceField.get(authorizationResponseHandler) as String

        assertNotEquals(
            "Wallet nonce should be different for every constructUnsignedVPTokenV1 call",
            firstNonce,
            secondNonce
        )
    }

    @Test
    fun `should successfully construct unsigned VP token for SD-JWT`() {
        val sdJwtVcList = listOf(sdJwtCredential1, sdJwtCredential2)
        val sdJwtCredentialMap = mapOf("sdjwt-input" to mapOf(VC_SD_JWT to sdJwtVcList))

        mockkConstructor(UnsignedSdJwtVPTokenBuilder::class)
        every { anyConstructed<UnsignedSdJwtVPTokenBuilder>().build(any()) } returns Pair(
            null,
            UnsignedSdJwtVPToken(
                mapOf(
                    "uuid-1" to unsignedKBJwt,
                    "uuid-2" to "mock-unsigned-kb-jwt"
                )
            )
        )

        val result = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = sdJwtCredentialMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )

        assertNotNull(result)
        assertTrue(result.containsKey(VC_SD_JWT))
        assertEquals(
            UnsignedSdJwtVPToken(
                mapOf(
                    "uuid-1" to unsignedKBJwt,
                    "uuid-2" to "mock-unsigned-kb-jwt"
                )
            ), result[VC_SD_JWT]
        )
    }

    @Test
    fun `should share SD-JWT VP successfully`() {
        val mockSigningResult = mockk<SdJwtVPTokenSigningResult>(relaxed = true)
        every { mockSigningResult.uuidToKbJWTSignature } returns mapOf("uuid-1" to "mock-signature")
        val mockUnsignedSdJwtVPToken = UnsignedSdJwtVPToken(
            uuidToUnsignedKBT = mapOf("uuid-1" to "mock-kb-jwt")
        )
        val mockVpTokenSigningPayload = mapOf("uuid-1" to sdJwtCredential1)

        val unsignedVPTokenMap = mapOf(
            "unsignedVPToken" to mockUnsignedSdJwtVPToken,
            "vpTokenSigningPayload" to mockVpTokenSigningPayload
        )
        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            mapOf(VC_SD_JWT to Pair(null, mockUnsignedSdJwtVPToken))
        )
        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                VC_SD_JWT to listOf(
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential1,
                        "sdjwt-input"
                    ).apply { identifier = "uuid-1" }
                )
            ))

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get("direct_post") } returns mockResponseHandler

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest.copy(responseType = "vp_token"),
            vpTokenSigningResults = mapOf(VC_SD_JWT to mockSigningResult),
            responseUri = responseUrl
        )

        assertEquals("success", result)


        verify(exactly = 1) {
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = any(),
                url = eq(responseUrl),
                authorizationResponse = any(),
                walletNonce = any()
            )
        }

    }

    @Test
    fun `should throw if SD-JWT format not found in unsigned tokens during shareVP`() {
        val mockSigningResult = mockk<SdJwtVPTokenSigningResult>(relaxed = true)

        setField(
            authorizationResponseHandler,
            "unsignedVPTokenResults",
            emptyMap<FormatType, Pair<Any?, UnsignedVPToken>>()
        )

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            authorizationResponseHandler.shareVP(
                authorizationRequest.copy(responseType = "vp_token"),
                mapOf(VC_SD_JWT to mockSigningResult),
                responseUrl
            )
        }
    }

    @Test
    fun `should share 2 SD-JWT credentials successfully`() {
        val sdJwt = UnsignedSdJwtVPToken(
            mapOf("uuid-1" to "kbjwt1", "uuid-2" to "kbjwt2")
        )

        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                VC_SD_JWT to listOf(
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential1,
                        "142"
                    ).apply { identifier = "uuid-1" },
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential2,
                        "143"
                    ).apply { identifier = "uuid-2" }
                )
            ))
        setField(
            authorizationResponseHandler, "unsignedVPTokenResults", mapOf(
                VC_SD_JWT to Pair(null, sdJwt)
            )
        )

        val signingResult = mockk<SdJwtVPTokenSigningResult>(relaxed = true)
        every { signingResult.uuidToKbJWTSignature } returns mapOf(
            "uuid-1" to "mock-signature",
            "uuid-2" to "mock-signature2"
        )
        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get(any()) } returns mockResponseHandler

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest.copy(responseType = "vp_token"),
            mapOf(VC_SD_JWT to signingResult),
            responseUrl
        )

        assertEquals("success", result)
    }

    @Test
    fun `should share 1 VC with vpToken as element and presentation submission correctly for vp_token response type`() {
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(mdocVPToken), listOf(
                DescriptorMap("input2", "mdoc_vp", "$[0]", null),
            ), 1
        )
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialMap2,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )
        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                MSO_MDOC to listOf(
                    CredentialInputDescriptorMapping(
                        MSO_MDOC,
                        mdocCredential,
                        "input2"
                    ).apply { identifier = "org.iso.18013.5.1.mDL" }
                )
            )
        )

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = mapOf(
                LDP_VC to ldpVPTokenSigningResult,
                MSO_MDOC to mdocVPTokenSigningResult,
                VC_SD_JWT to sdJwtVPTokenSigningResult
            ),
            responseUri = responseUrl
        )

        // assert if mockResponseHandler is called with correct authorization response
        verify(exactly = 1) {
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = any(),
                url = eq(responseUrl),
                authorizationResponse = match {
                    // Note: If only one vp token is being shared then tha path in the presentation submission takes value as $ and VP token is an element only and not array
                    assertEquals(
                        "VPTokenElement(value=MdocVPToken(base64EncodedDeviceResponse=base64EncodedDeviceResponse))",
                        it.vpToken.toString()
                    )
                    assertEquals(
                        "PresentationSubmission(id=649d581c-f291-4969-9cd5-2c27385a348f, definitionId=649d581c-f891-4969-9cd5-2c27385a348f, descriptorMap=[DescriptorMap(id=input2, format=mdoc_vp, path=$, pathNested=null)])",
                        it.presentationSubmission.toString()
                    )
                    it.presentationSubmission.descriptorMap.size == 1
                },
                walletNonce = any()
            )
        }
    }

// sharing of multiple credentials of different formats

    @Test
    fun `should share credentials for 2LDP, 2SD-JWT and 2MSO-MDOC VC`() {
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build(any()) } returns Pair(
            vpTokenSigningPayload2,
            unsignedLdpVPToken
        )
        every {
            anyConstructed<LdpVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(ldpVPToken2), listOf(
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", "$.verifiableCredential[0]")
                ),
                DescriptorMap(
                    "input1",
                    "ldp_vp",
                    "$[2]",
                    PathNested("input1", "ldp_vc", "$.verifiableCredential[1]")
                )
            ), 2
        )
        every {
            anyConstructed<MdocVPTokenBuilder>().build(
                any(),
                any(),
                any(),
                any()
            )
        } returns Triple(
            listOf(mdocVPToken), listOf(
                DescriptorMap("input2", "mdoc_vp", "$[3]", null),
            ), 4
        )


        val unsignedtokens = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialMap2,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite,
            nonce = walletNonce
        )
        print(unsignedtokens)
        setField(
            authorizationResponseHandler, "formatToCredentialInputDescriptorMapping", mapOf(
                LDP_VC to listOf(
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential1, "input1"),
                    CredentialInputDescriptorMapping(LDP_VC, ldpCredential2, "input1")
                ),
                MSO_MDOC to listOf(
                    CredentialInputDescriptorMapping(
                        MSO_MDOC,
                        mdocCredential,
                        "input2"
                    ).apply { identifier = "org.iso.18013.5.1.mDL" }
                ),
                VC_SD_JWT to listOf(
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential1,
                        "input3"
                    ).apply { identifier = "123" },
                    CredentialInputDescriptorMapping(
                        VC_SD_JWT,
                        sdJwtCredential2,
                        "input3"
                    ).apply { identifier = "456" }
                )
            )
        )

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = mapOf(
                LDP_VC to ldpVPTokenSigningResult,
                MSO_MDOC to mdocVPTokenSigningResult,
                VC_SD_JWT to sdJwtVPTokenSigningResult
            ),
            responseUri = responseUrl
        )

        assertEquals("success", result)
        // assert if mockResponseHandler is called with correct authorization response
        verify(exactly = 1) {
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = any(),
                url = eq(responseUrl),
                authorizationResponse = match {
                    // Note: If only more than vp token is being shared then the path in presentation submission takes value as $[<index>] and VP token is an array holding all tokens together
                    val jsonAuthorizationResponse = Json.encodeToString(it.toJsonEncodedMap())
                    assertEquals(
                        """
                    {"vp_token":"[{\"@context\":[\"context\"],\"type\":[\"type\"],\"verifiableCredential\":[{\"id\":\"did:rcw:38d51ff1-c55d-40be-af56-c3f30aaa81d4\",\"type\":[\"VerifiableCredential\",\"InsuranceCredential\"],\"proof\":{\"type\":\"Ed25519Signature2020\",\"created\":\"2025-05-12T10:51:03Z\",\"proofValue\":\"z62rZ8pWHi1PmkGYzZmgF8sQoLCPwwfvXYmSsC7P6KoaVyAoDv1SRi1VomcQqSv41HvkHKrHUfpJX3K3ZU9G1rVoh\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39#key-0\"},\"issuer\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39\",\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://holashchand.github.io/test_project/insurance-context.json\",\"https://w3id.org/security/suites/ed25519-2020/v1\"],\"issuanceDate\":\"2025-05-12T10:51:02.820Z\",\"expirationDate\":\"2025-06-11T10:51:02.814Z\",\"credentialSubject\":{\"id\":\"did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6Ii1zUVpsbDhYQXBySGVlNG5CdzB5TUwtLTdsOFJBNGhaM2dMclkzMzdtVUUiLCJhbGciOiJSUzI1NiIsIm4iOiJrUHllWHdIMVM3cjE3WmhOMkl3YmhZejR6bnNEVnl3bDdLRzllUjZ3bUM1YUtaZ0dyY18yWXB1V28tT2RuWDhOc3VWLWFzU0NjU01FVThVdUZqNWtienhRRGdPWFNQWlI1MHVCS19TVEtXTHNVenVlRHpQZUpGdDhibWItVjgtQ0FOa2JrSGRYbXVSS0pUU0JVd3lWRXdtTERnb0ZLYTlVLXhjVTVELWFDcHJFVS1fQ1oyUGZDcF9jdmtJNmdOS2FKRHJBcVVlUkVQYzAzbl93WXd0bE82S1RhQ25jc0JMbEp2U1NBM1B1ZEN5ZFFMVUZwak12R2d3VUlFNkg3d3FoTGdZeXZLTVBTYzVEMG8ybWZ0cHNTVFNrY3p2OEVPdnMtNU5kaHZXTXFlc0dtSE5helk5bDhOMFQyWGxrM0ZqM1lDcXNmQ1lnLUd1RkFRaXpZOU1ZV3cifQ==\",\"dob\":\"2025-01-01\",\"email\":\"abcd@gmail.com\",\"gender\":\"Male\",\"mobile\":\"0123456789\",\"benefits\":[\"Critical Surgery\",\"Full body checkup\"],\"fullName\":\"wallet\",\"policyName\":\"wallet\",\"policyNumber\":\"5555\",\"policyIssuedOn\":\"2023-04-20\",\"policyExpiresOn\":\"2033-04-20\"}},{\"id\":\"did:rcw:da2d0059-cce8-4bad-923a-217cd381dbd2\",\"type\":[\"VerifiableCredential\",\"InsuranceCredential\"],\"proof\":{\"type\":\"Ed25519Signature2020\",\"created\":\"2025-05-12T10:51:44Z\",\"proofValue\":\"z3rACCjPw79KfPSYGasCVpqyWUpUhEYzPcmo2QLoVtj6LYUxpXi22UBcQdNSFbd3YedVrysS5Svzgcy1uYJEiVPKA\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39#key-0\"},\"issuer\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39\",\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://holashchand.github.io/test_project/insurance-context.json\",\"https://w3id.org/security/suites/ed25519-2020/v1\"],\"issuanceDate\":\"2025-05-12T10:51:44.739Z\",\"expirationDate\":\"2025-06-11T10:51:44.734Z\",\"credentialSubject\":{\"id\":\"did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6Ii1zUVpsbDhYQXBySGVlNG5CdzB5TUwtLTdsOFJBNGhaM2dMclkzMzdtVUUiLCJhbGciOiJSUzI1NiIsIm4iOiJrUHllWHdIMVM3cjE3WmhOMkl3YmhZejR6bnNEVnl3bDdLRzllUjZ3bUM1YUtaZ0dyY18yWXB1V28tT2RuWDhOc3VWLWFzU0NjU01FVThVdUZqNWtienhRRGdPWFNQWlI1MHVCS19TVEtXTHNVenVlRHpQZUpGdDhibWItVjgtQ0FOa2JrSGRYbXVSS0pUU0JVd3lWRXdtTERnb0ZLYTlVLXhjVTVELWFDcHJFVS1fQ1oyUGZDcF9jdmtJNmdOS2FKRHJBcVVlUkVQYzAzbl93WXd0bE82S1RhQ25jc0JMbEp2U1NBM1B1ZEN5ZFFMVUZwak12R2d3VUlFNkg3d3FoTGdZeXZLTVBTYzVEMG8ybWZ0cHNTVFNrY3p2OEVPdnMtNU5kaHZXTXFlc0dtSE5helk5bDhOMFQyWGxrM0ZqM1lDcXNmQ1lnLUd1RkFRaXpZOU1ZV3cifQ==\",\"dob\":\"2025-01-01\",\"email\":\"abcd@gmail.com\",\"gender\":\"Male\",\"mobile\":\"0123456789\",\"benefits\":[\"Critical Surgery\",\"Full body checkup\"],\"fullName\":\"wallet\",\"policyName\":\"wallet\",\"policyNumber\":\"5555\",\"policyIssuedOn\":\"2023-04-20\",\"policyExpiresOn\":\"2033-04-20\"}}],\"id\":\"id\",\"holder\":\"holder\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-02-13T10:00:00Z\",\"challenge\":\"bMHvX1HGhbh8zqlSWf/fuQ==\",\"domain\":\"https://123\",\"proofPurpose\":\"authentication\",\"verificationMethod\":\"-----BEGIN RSA PUBLIC KEY-----publickey-----END RSA PUBLIC KEY-----\"}},\"base64EncodedDeviceResponse\",\"eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJmYW1pbHlfbmFtZSI6IkRvZSIsInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiIxMjMgTWFpbiBTdCIsImxvY2FsaXR5IjoiQW55dG93biIsIl9zZCI6WyJOSm5tY3QwQnFCTUUxSmZCbEM2alJRVlJ1ZXZwRU9OaVl3N0E3TUh1SnlRIiwib201Wnp0WkhCLUdkMDBMRzIxQ1ZfeE00RmFFTlNvaWFPWG5UQUpOY3pCNCJdfSwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifX0sImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyLCJfc2QiOlsiMUN1cjJrMkEyb0lCNUNzaFNJZl9BX0tnLWwyNnVfcUt1V1E3OVAwVmRhcyIsIlIxelRVdk9ZSGdjZXBqMGpIeXBHSHo5RUh0dFZLZnQweXN3YmM5RVRQYlUiLCJlRHFRcGRUWEpYYldoZi1Fc0k3enc1WDZPdlltRk4tVVpRUU1lc1h3S1B3IiwicGREazJfWEFLSG83Z09BZndGMWI3T2RDVVZUaXQya0pIYXhTRUNROXhmYyIsInBzYXVLVU5XRWkwOW51M0NsODl4S1hnbXBXRU5abDV1eTFOMW55bl9qTWsiLCJzTl9nZTBwSFhGNnFtc1luWDFBOVNkd0o4Y2g4YUVOa3hiT0RzVDc0WXdJIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.Kkhrxy2acd52JTl4g_0x25D5d1QNCTbqHrD9Qu9HzXMxPMu_5T4z-cSiutDYb5cIdi9NzMXPe4MXax-fUymEDg~WyJzYWx0IiwicmVnaW9uIiwiQW55c3RhdGUiXQ~WyJzYWx0IiwiY291bnRyeSIsIlVTIl0~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJzYWx0IiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~WyJzYWx0IiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl82NSIsdHJ1ZV0~unsignedKBT1.sig1\",\"eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk4VWw4ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBTQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il19.eyJjcmVkZW50aWFsX3R5cGUiOiJNU0lTRE4iLCJuYmYiOjE3NTI5ODQ3MzcsImV4cCI6MTc4NTM4NDczNywidmN0IjoiZXUuZXVyb3BhLmVjLmV1ZGkubXNpc2RuLjEiLCJjbmYiOnsia2lkIjoiZGlkOmp3azpleUpyZEhraU9pSkZReUlzSW1OeWRpSTZJbEF0TWpVMklpd2llQ0k2SWxKUk5XSkRiMngzUkZKV1pHUjRhbkk1TFUweUxVNUtPRVZ1TjFwSE1tTXpVbkZzVTJKVVR6TlJUMFVpTENKNUlqb2lZVlpFVVZkak5TMUJZbmhIYmxoV2JYRk1WMkphWmpGR1ZsWjFOVEF5TW0xaGFHdHpSVTh3VTJSZmR5SXNJblZ6WlNJNkluTnBaeUo5IzAifSwiaXNzIjoiaHR0cHM6Ly9mdW5rZS5hbmltby5pZCIsImlhdCI6MTc1Mzk0MjUyNywiX3NkIjpbIjI5SXE0b29UNzhGMkI1bFI1RzhGSGhGWWJKWmlER29vRHEySUpicFpCVG8iLCIzZVNTOEtZcUZzQVVHZVhIVWhwU21qd1k2TG5XaVJCMTVXYXRLY0ZTNzhJIiwiNE9mZGdDalZPUTJMbzhESXpTUEpodVVWT25yWGhjX1dkTGpCZDcwRGJFUSIsIkFwMWVweTdtVThiRkdrNXZkWXdlMjZma2pUY2taaW1uMDlncFlSR25XY3ciLCJEU0NWZHY3WklSOEZNNTR4c05MVlZqYndJc0JjcE9EUllHRTlCOTFra19RIiwiRnMwbGVHT0VMUU85ejhYblZsbVJTdXRUX0d3dDRTOWNubUJLcDF4TnRyQSIsIlFTbjl3dUx3LUJKY3VLRF9URHl0NGcyZlR4LU1KcmNyVzM0bVpKdHhtc0kiLCJfZDkyZVNKcW9FemdhQlctcFU2NUY2N3FOUno2Y2owRkJObDJYcTFmRWdFIiwia3VwOXhVUjZYMDZ5X3RiVVBPTzJ4VWxiWHJReG1qalRiVE9zMktYUUM4YyIsInBIYmh1eWxJbkZnaGtPY3hqcHVKb0o0S0hITUhfT2JSOWxYX0ZUa2Vmb2ciLCJ4YW1wZmJkRHJfd05LUllKN1F6NlAxZEZJcGJvMTJFdHRfZkMzYko4MDFvIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.pf3MHMEAma64_-8mfmPdLCNzgzz5K0_EianTPd5IUzMlkXhB1v4NtQmRiARlLvTd9kkUChhW4lascAkW8TOnSA~WyI4NzY3MzA2NTE3OTE1MTMzMTI2NDI5MTUiLCJwaG9uZV9udW1iZXIiLCI0OTE1MTEyMzQ1NjciXQ~WyIyNzgzODk0ODU5Mjc2ODY0NTY1NjkxNzUiLCJyZWdpc3RlcmVkX2ZhbWlseV9uYW1lIiwiTXVzdGVybWFuIl0~WyI5Njk4OTYzODY5MDAwMTE3MzM0MTE0NDQiLCJyZWdpc3RlcmVkX2dpdmVuX25hbWUiLCJKb2huIE1pY2hhZWwiXQ~WyIxMDE3NzAzNzY5OTU2Mzc0MjI4NTIwMDQ4IiwiY29udHJhY3Rfb3duZXIiLHRydWVd~WyIxMTcwMTg2ODQ0MTkyNTczMzQyOTYyNDg5IiwiZW5kX3VzZXIiLGZhbHNlXQ~WyI0MzI1MjkxNDE2MzczOTU0MzgxNDM5NTUiLCJtb2JpbGVfb3BlcmF0b3IiLCJUZWxla29tX0RFIl0~WyI2ODA1NjkyNDQ3MTA1NjQ3ODc1ODQxNzUiLCJpc3N1aW5nX29yZ2FuaXphdGlvbiIsIlRlbE9yZyJd~WyI5MzE5ODU3NzkxNTk0Njc0ODE2NTg4ODciLCJ2ZXJpZmljYXRpb25fZGF0ZSIsIjIwMjMtMDgtMjUiXQ~WyI2MTkxMTk5NjI3Mzg2MDQ5MjI4ODkwMjEiLCJ2ZXJpZmljYXRpb25fbWV0aG9kX2luZm9ybWF0aW9uIiwiTnVtYmVyVmVyaWZ5Il0~WyIzNzM2NzUzNDQwNDA1ODI4Mzc2MTE0MjQiLCJpc3N1YW5jZV9kYXRlIiwiMjAyNS0wNy0yMFQwNDoxMjoxNy4wODlaIl0~WyI1NjU0NDMyNzk2MjEwMjQ2ODk0NjQ3MDgiLCJleHBpcnlfZGF0ZSIsIjIwMjYtMDctMzBUMDQ6MTI6MTcuMDg5WiJd~unsignedKBT2.sig2\"]","presentation_submission":"{\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"definition_id\":\"649d581c-f891-4969-9cd5-2c27385a348f\",\"descriptor_map\":[{\"id\":\"input1\",\"format\":\"ldp_vp\",\"path\":\"${'$'}[2]\",\"path_nested\":{\"id\":\"input1\",\"format\":\"ldp_vc\",\"path\":\"${'$'}.verifiableCredential[0]\"}},{\"id\":\"input1\",\"format\":\"ldp_vp\",\"path\":\"${'$'}[2]\",\"path_nested\":{\"id\":\"input1\",\"format\":\"ldp_vc\",\"path\":\"${'$'}.verifiableCredential[1]\"}},{\"id\":\"input2\",\"format\":\"mdoc_vp\",\"path\":\"${'$'}[3]\"},{\"id\":\"input3\",\"format\":\"vc+sd-jwt\",\"path\":\"${'$'}[4]\"},{\"id\":\"input3\",\"format\":\"vc+sd-jwt\",\"path\":\"${'$'}[5]\"}]}","state":"fsnC8ixCs6mWyV+00k23Qg=="}
                        """.trimIndent(), jsonAuthorizationResponse
                    )
                    true
                },
                walletNonce = any()
            )
        }
    }


}
