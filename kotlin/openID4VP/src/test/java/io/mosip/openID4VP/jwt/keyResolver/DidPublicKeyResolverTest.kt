package io.mosip.openID4VP.jwt.keyResolver

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.exception.JWSException
import io.mosip.openID4VP.jwt.keyResolver.types.DidPublicKeyResolver
import io.mosip.vercred.vcverifier.DidWebResolver
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.DidResolutionFailed
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertThrows

class DidPublicKeyResolverTest {
    private lateinit var  resolver : DidPublicKeyResolver
    @Before
    fun setUp() {

        val mockDidUrl = "did:web:example:123456789#keys-1"
         mockkConstructor(DidWebResolver::class)
        resolver = DidPublicKeyResolver(mockDidUrl)

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

    @Test
    fun `should return public key when kid matches`() {
        val mockResponse =
            mapOf(
                "verificationMethod" to listOf(
                    mapOf(
                        "id" to "did:web:example:123456789#keys-1",
                        "publicKey" to "mockPublicKey123"
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
        every { anyConstructed<DidWebResolver>().resolve()} returns mapOf("didDocument" to "mockResponse")

        val exception = assertThrows(OpenID4VPExceptions.KidExtractionFailed::class.java) {
            resolver.resolveKey(emptyMap())
        }
        assertEquals(
            "KID extraction from DID document failed",
            exception.message
        )
    }

    @Test
    fun `should throw exception did resolution fails`() {
        every { anyConstructed<DidWebResolver>().resolve()} throws DidResolutionFailed("Did document could not be fetched")

        val exception = assertThrows(OpenID4VPExceptions.PublicKeyResolutionFailed::class.java) {
            resolver.resolveKey(emptyMap())
        }
        assertEquals(
            "Did document could not be fetched",
            exception.message
        )
    }

    @Test
    fun `should throw exception when public key extraction fails`() {
        val mockResponse =
            mapOf(
                "verificationMethod" to listOf(
                    mapOf(
                        "id" to "did:web:example:123456789#keys-1",
                    )
                )
            )
        every { anyConstructed<DidWebResolver>().resolve() }  returns mockResponse

        val header = mapOf("kid" to "did:example:123456789#keys-1")

        val exception =
            assertThrows(OpenID4VPExceptions.PublicKeyExtractionFailed::class.java) {
                resolver.resolveKey(header)
            }
        assertEquals(
            "Public key extraction failed",
            exception.message
        )
    }

}

