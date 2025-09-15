package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.mapping.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.testData.ldpVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.constants.FormatType
import kotlin.test.*

class LdpVPTokenBuilderTest {

    private lateinit var mockLdpVPTokenSigningResult: LdpVPTokenSigningResult
    private lateinit var mockUnsignedLdpVPToken: VPTokenSigningPayload
    private lateinit var mockProof: Proof
    private val testNonce = "test-nonce-123"

    @BeforeTest
    fun setUp() {
        mockProof = Proof(
            type = "Ed25519Signature2020",
            created = "2023-01-01T12:00:00Z",
            verificationMethod = "did:example:123#key-1",
            proofPurpose = "authentication",
            challenge = testNonce,
            proofValue = null,
            jws = null,
            domain = "example.com"
        )

        mockUnsignedLdpVPToken = VPTokenSigningPayload(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = listOf(mapOf("id" to "vc-1")),
            id = "vpId-123",
            holder = "did:example:123",
            proof = mockProof
        )

        mockLdpVPTokenSigningResult = LdpVPTokenSigningResult(
            jws = null,
            proofValue = "test-proof-value-123",
            signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )
    }

    @Test
    fun `should build LdpVPToken with Ed25519Signature2020 successfully - old`() {
        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            mockUnsignedLdpVPToken,
            testNonce
        )

        val result = builder.build()

        assertNotNull(result)
        assertEquals(mockUnsignedLdpVPToken.context, result.context)
        assertEquals(mockUnsignedLdpVPToken.type, result.type)
        assertEquals(mockUnsignedLdpVPToken.verifiableCredential, result.verifiableCredential)
        assertEquals(mockUnsignedLdpVPToken.id, result.id)
        assertEquals(mockUnsignedLdpVPToken.holder, result.holder)
        assertEquals(mockLdpVPTokenSigningResult.proofValue, result.proof?.proofValue)
        assertEquals(null, result.proof?.jws)
    }

    @Test
    fun `should build LdpVPToken with Ed25519Signature2020 successfully`() {
        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            mockUnsignedLdpVPToken,
            testNonce
        )

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(FormatType.LDP_VC, mockUnsignedLdpVPToken.verifiableCredential[0], "input-descriptor-id1")
            ),
            unsignedVPTokenResult = Pair(mockUnsignedLdpVPToken, UnsignedLdpVPToken(listOf(mockUnsignedLdpVPToken).toString())),
            vpTokenSigningResult = mockLdpVPTokenSigningResult,
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(mockUnsignedLdpVPToken.context, vpToken.context)
        assertEquals(mockUnsignedLdpVPToken.type, vpToken.type)
        assertEquals(mockUnsignedLdpVPToken.verifiableCredential, vpToken.verifiableCredential)
        assertEquals(mockUnsignedLdpVPToken.id, vpToken.id)
        assertEquals(mockUnsignedLdpVPToken.holder, vpToken.holder)
        assertEquals(mockLdpVPTokenSigningResult.proofValue, vpToken.proof?.proofValue)
        assertEquals(null, vpToken.proof?.jws)
        assertEquals( """DescriptorMap(id=input-descriptor-id1, format=ldp_vp, path=${'$'}[0], pathNested=null)""", descriptorMaps.first().toString())
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should build LdpVPToken with JsonWebSignature2020 successfully - old`() {
        mockLdpVPTokenSigningResult = LdpVPTokenSigningResult(
            jws = "test-jws-signature",
            proofValue = null,
            signatureAlgorithm = SignatureSuiteAlgorithm.JsonWebSignature2020.value
        )

        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            mockUnsignedLdpVPToken,
            testNonce
        )

        val result = builder.build()

        assertNotNull(result)
        assertEquals(mockLdpVPTokenSigningResult.jws, result.proof?.jws)
        assertEquals(null, result.proof?.proofValue)
    }

    @Test
    fun `should build LdpVPToken with JsonWebSignature2020 successfully`() {
        mockLdpVPTokenSigningResult = LdpVPTokenSigningResult(
            jws = "test-jws-signature",
            proofValue = null,
            signatureAlgorithm = SignatureSuiteAlgorithm.JsonWebSignature2020.value
        )

        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            mockUnsignedLdpVPToken,
            testNonce
        )

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(FormatType.LDP_VC, mockUnsignedLdpVPToken.verifiableCredential[0], "input-descriptor-id1")
            ),
            unsignedVPTokenResult = Pair(mockUnsignedLdpVPToken, UnsignedLdpVPToken(listOf(mockUnsignedLdpVPToken).toString())),
            vpTokenSigningResult = mockLdpVPTokenSigningResult,
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(mockLdpVPTokenSigningResult.jws, vpToken.proof?.jws)
        assertEquals(null, vpToken.proof?.proofValue)
        assertEquals( """DescriptorMap(id=input-descriptor-id1, format=ldp_vp, path=${'$'}[0], pathNested=null)""", descriptorMaps.first().toString())
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should build LdpVPToken with RSASignature2018 successfully - old`() {
        mockLdpVPTokenSigningResult = LdpVPTokenSigningResult(
            jws = "test-rsa-signature",
            proofValue = null,
            signatureAlgorithm = SignatureSuiteAlgorithm.RSASignature2018.value
        )

        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            mockUnsignedLdpVPToken,
            testNonce
        )

        val result = builder.build()

        assertNotNull(result)
        assertEquals(mockLdpVPTokenSigningResult.jws, result.proof?.jws)
    }

    @Test
    fun `should build LdpVPToken with RSASignature2018 successfully`() {
        mockLdpVPTokenSigningResult = LdpVPTokenSigningResult(
            jws = "test-rsa-signature",
            proofValue = null,
            signatureAlgorithm = SignatureSuiteAlgorithm.RSASignature2018.value
        )

        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            mockUnsignedLdpVPToken,
            testNonce
        )

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(FormatType.LDP_VC, mockUnsignedLdpVPToken.verifiableCredential[0], "input-descriptor-id1")
            ),
            unsignedVPTokenResult = Pair(mockUnsignedLdpVPToken, UnsignedLdpVPToken(listOf(mockUnsignedLdpVPToken).toString())),
            vpTokenSigningResult = mockLdpVPTokenSigningResult,
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(mockLdpVPTokenSigningResult.jws, vpToken.proof?.jws)
        assertEquals( """DescriptorMap(id=input-descriptor-id1, format=ldp_vp, path=${'$'}[0], pathNested=null)""", descriptorMaps.first().toString())
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should build LdpVPToken with Ed25519Signature2018 successfully - old`() {
        mockLdpVPTokenSigningResult = LdpVPTokenSigningResult(
            jws = "test-ed25519-2018-signature",
            proofValue = null,
            signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2018.value
        )

        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            mockUnsignedLdpVPToken,
            testNonce
        )

        val result = builder.build()

        assertNotNull(result)
        assertEquals(mockLdpVPTokenSigningResult.jws, result.proof?.jws)
    }

    @Test
    fun `should build LdpVPToken with Ed25519Signature2018 successfully`() {
        mockLdpVPTokenSigningResult = LdpVPTokenSigningResult(
            jws = "test-ed25519-2018-signature",
            proofValue = null,
            signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2018.value
        )
        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            mockUnsignedLdpVPToken,
            testNonce
        )

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(FormatType.LDP_VC, mockUnsignedLdpVPToken.verifiableCredential[0], "input-descriptor-id1")
            ),
            unsignedVPTokenResult = Pair(mockUnsignedLdpVPToken, UnsignedLdpVPToken(listOf(mockUnsignedLdpVPToken).toString())),
            vpTokenSigningResult = mockLdpVPTokenSigningResult,
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(mockLdpVPTokenSigningResult.jws, vpToken.proof?.jws)
        assertEquals( """DescriptorMap(id=input-descriptor-id1, format=ldp_vp, path=${'$'}[0], pathNested=null)""", descriptorMaps.first().toString())
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should use existing LdpVPToken from testData - old`() {
        val testToken = ldpVPToken as LdpVPToken
        val unsignedToken = VPTokenSigningPayload(
            context = testToken.context,
            type = testToken.type,
            verifiableCredential = testToken.verifiableCredential,
            id = testToken.id,
            holder = testToken.holder,
            proof = testToken.proof?.apply {
                proofValue = null
                jws = null
            }
        )

        val signingResult = LdpVPTokenSigningResult(
            jws = null,
            proofValue = "new-proof-value",
            signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )

        val builder = LdpVPTokenBuilder(signingResult, unsignedToken, "test-nonce")

        val result = builder.build()

        assertNotNull(result)
        assertEquals(testToken.context, result.context)
        assertEquals(testToken.type, result.type)
        assertEquals(testToken.verifiableCredential, result.verifiableCredential)
        assertEquals(testToken.id, result.id)
        assertEquals(testToken.holder, result.holder)
        assertEquals("new-proof-value", result.proof?.proofValue)
    }

    @Test
    fun `should use existing LdpVPToken from testData`() {
        val testToken = ldpVPToken as LdpVPToken
        val unsignedToken = VPTokenSigningPayload(
            context = testToken.context,
            type = testToken.type,
            verifiableCredential = testToken.verifiableCredential,
            id = testToken.id,
            holder = testToken.holder,
            proof = testToken.proof?.apply {
                proofValue = null
                jws = null
            }
        )

        val signingResult = LdpVPTokenSigningResult(
            jws = null,
            proofValue = "new-proof-value",
            signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2020.value
        )
        val builder = LdpVPTokenBuilder(signingResult, unsignedToken, "test-nonce")

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(FormatType.LDP_VC, unsignedToken.verifiableCredential[0], "input-descriptor-id1")
            ),
            unsignedVPTokenResult = Pair(unsignedToken, UnsignedLdpVPToken(listOf(unsignedToken).toString())),
            vpTokenSigningResult = signingResult,
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals( """DescriptorMap(id=input-descriptor-id1, format=ldp_vp, path=${'$'}[0], pathNested=null)""", descriptorMaps.first().toString())
        assertEquals(1, nextIndex)
        assertEquals(testToken.context, vpToken.context)
        assertEquals(testToken.type, vpToken.type)
        assertEquals(testToken.verifiableCredential, vpToken.verifiableCredential)
        assertEquals(testToken.id, vpToken.id)
        assertEquals(testToken.holder, vpToken.holder)
        assertEquals("new-proof-value", vpToken.proof?.proofValue)
    }

    @Test
    fun `should handle null proof in unsigned token - old`() {
        val unsignedTokenWithNullProof = mockUnsignedLdpVPToken.copy(proof = null)

        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            unsignedTokenWithNullProof,
            testNonce
        )

        assertFailsWith<NullPointerException> {
            builder.build()
        }
    }

    @Test
    fun `should handle null proof in unsigned token`() {
        val payloadWithNullProof = mockUnsignedLdpVPToken.copy(proof = null)

        val builder = LdpVPTokenBuilder(
            mockLdpVPTokenSigningResult,
            payloadWithNullProof,
            testNonce
        )

        assertFailsWith<NullPointerException> {
            builder.build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(FormatType.LDP_VC, mockUnsignedLdpVPToken.verifiableCredential[0], "input-descriptor-id1")
                ),
                unsignedVPTokenResult = Pair(payloadWithNullProof, UnsignedLdpVPToken(listOf(payloadWithNullProof).toString())),
                vpTokenSigningResult = mockLdpVPTokenSigningResult,
                rootIndex = 0
            )
        }
    }

    @Test
    fun `should build LdpVPToken using build method and return correct vp token, descriptor map & next index`() {
        val mapping = io.mosip.openID4VP.authorizationResponse.mapping.CredentialInputDescriptorMapping(
            format = io.mosip.openID4VP.constants.FormatType.LDP_VC,
            credential = mockUnsignedLdpVPToken.verifiableCredential[0],
            inputDescriptorId = "input-descriptor-id1"
        )
        val unsignedVPTokenResult = Pair(mockUnsignedLdpVPToken, UnsignedLdpVPToken(listOf(mockUnsignedLdpVPToken).toString()))
        val builder = LdpVPTokenBuilder(mockLdpVPTokenSigningResult, mockUnsignedLdpVPToken, testNonce)
        val result = builder.build(
            credentialInputDescriptorMappings = listOf(mapping),
            unsignedVPTokenResult = unsignedVPTokenResult,
            vpTokenSigningResult = mockLdpVPTokenSigningResult,
            rootIndex = 0
        )
        assertNotNull(result)
        assertEquals(1, result.first.size) // contains 1 ldp_token
        assertEquals(1, result.second.size) // contains 1 descriptor map as its only 1 credential
        assertEquals(1, result.third) // next root index should be 1 (0 + 1)
        assertEquals("input-descriptor-id1", result.second[0].id)
        assertEquals(io.mosip.openID4VP.constants.VPFormatType.LDP_VP.value, result.second[0].format)
    }

    private fun ldpVPToken(vpTokens: List<VPToken>): LdpVPToken {
        assertNotNull(vpTokens)
        assertTrue(vpTokens.size == 1)
        val vpToken = vpTokens.first() as LdpVPToken
        return vpToken
    }
}
