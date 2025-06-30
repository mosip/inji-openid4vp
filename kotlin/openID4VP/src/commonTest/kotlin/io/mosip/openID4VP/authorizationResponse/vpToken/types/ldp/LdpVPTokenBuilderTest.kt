package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.testData.ldpVPToken
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
            signatureAlgorithm = SignatureAlgorithm.Ed25519Signature2020.value
        )
    }

    @Test
    fun `should build LdpVPToken with Ed25519Signature2020 successfully`() {
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
    fun `should build LdpVPToken with JsonWebSignature2020 successfully`() {
        mockLdpVPTokenSigningResult = LdpVPTokenSigningResult(
            jws = "test-jws-signature",
            proofValue = null,
            signatureAlgorithm = SignatureAlgorithm.JsonWebSignature2020.value
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
    fun `should build LdpVPToken with RSASignature2018 successfully`() {
        mockLdpVPTokenSigningResult = LdpVPTokenSigningResult(
            jws = "test-rsa-signature",
            proofValue = null,
            signatureAlgorithm = SignatureAlgorithm.RSASignature2018.value
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
            signatureAlgorithm = SignatureAlgorithm.Ed25519Signature2018.value
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
            signatureAlgorithm = SignatureAlgorithm.Ed25519Signature2020.value
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
    fun `should handle null proof in unsigned token`() {
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
}
