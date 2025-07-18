package io.mosip.openID4VP.jwt.keyResolver

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkConstructor
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.jwt.keyResolver.types.DidPublicKeyResolver
import io.mosip.vercred.vcverifier.DidWebResolver
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.DidResolutionFailed
import kotlin.test.*

class DidPublicKeyResolverTest {

    private lateinit var resolver: DidPublicKeyResolver

    @BeforeTest
    fun setUp() {
        val mockDidUrl = "did:web:example:123456789#keys-1"
        mockkConstructor(DidWebResolver::class)
        resolver = DidPublicKeyResolver(mockDidUrl)


    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should return public key when kid matches`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf(
                    "id" to "did:web:example:123456789#keys-1",
                    "publicKeyMultibase" to "mockPublicKey123"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:example:123456789#keys-1")
        val result = resolver.resolveKey(header)

        assertEquals("mockPublicKey123", result)
    }

    @Test
    fun `should throw exception when kid is missing`() {
        every { anyConstructed<DidWebResolver>().resolve() } returns mapOf("didDocument" to "mockResponse")

        val exception = assertFailsWith<KidExtractionFailed> {
            resolver.resolveKey(emptyMap())
        }
        assertEquals("KID extraction from DID document failed", exception.message)
    }

    @Test
    fun `should throw exception when did resolution fails`() {
        every { anyConstructed<DidWebResolver>().resolve() } throws DidResolutionFailed("Did document could not be fetched")

        val exception = assertFailsWith<PublicKeyResolutionFailed> {
            resolver.resolveKey(emptyMap())
        }
        assertEquals("Did document could not be fetched", exception.message)
    }

    @Test
    fun `should throw exception when public key extraction fails`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("id" to "did:web:example:123456789#keys-1") // No "publicKey"
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:example:123456789#keys-1")

        val exception = assertFailsWith<PublicKeyExtractionFailed> {
            resolver.resolveKey(header)
        }
        assertEquals("Public key extraction failed for kid: did:example:123456789#keys-1", exception.message)
    }

    @Test
    fun `should throw exception when publicKeyMultibase is empty  verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyMultibase" to  "",
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<InvalidData> {
            resolver.resolveKey(header)
        }
        assertEquals("publicKeyMultibase cannot be null or empty", exception.message)
    }

    @Test
    fun `should throw exception when publicKeyMultibase is null  verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyMultibase" to  null,
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<InvalidData> {
            resolver.resolveKey(header)
        }
        assertEquals("publicKeyMultibase cannot be null or empty", exception.message)
    }

    @Test
    fun `should throw exception when unsupported public key- publicKeyHex present in verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyHex" to  "z3CSkXmF1DmgVuqPFKMTuJgn846mEuVB9rNoyP9hXribo",
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<UnsupportedPublicKeyType> {
            resolver.resolveKey(header)
        }
        assertEquals("Unsupported Public Key type. Supported: publicKeyMultibase", exception.message)
    }

    @Test
    fun `should throw exception when unsupported public key- publicKeyJwk present in verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyJwk" to  "z3CSkXmF1DmgVuqPFKMTuJgn846mEuVB9rNoyP9hXribo",
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<UnsupportedPublicKeyType> {
            resolver.resolveKey(header)
        }
        assertEquals("Unsupported Public Key type. Supported: publicKeyMultibase", exception.message)
    }

    @Test
    fun `should throw exception when unsupported public key- publicKeyPem present in verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyPem" to  "z3CSkXmF1DmgVuqPFKMTuJgn846mEuVB9rNoyP9hXribo",
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<UnsupportedPublicKeyType> {
            resolver.resolveKey(header)
        }
        assertEquals("Unsupported Public Key type. Supported: publicKeyMultibase", exception.message)
    }
}
