package io.mosip.openID4VP.jwt.keyResolver

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.jwt.exception.JWTVerificationException
import io.mosip.openID4VP.jwt.keyResolver.types.DidKeyResolver
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows


class DidKeyResolverTest {
    private lateinit var  resolver : DidKeyResolver
    @Before
    fun setUp() {

        mockkObject(NetworkManagerClient.Companion)
        val mockDidUrl = "did:example:123456789"
        resolver = DidKeyResolver(mockDidUrl)

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
        val mockResponse = """{
            "didDocument": {
                "verificationMethod": [
                    {"id": "did:example:123456789#keys-1", "publicKey": "mockPublicKey123"}
                ]
            }
        }"""
        every { NetworkManagerClient.sendHTTPRequest(any(), any()) } returns mapOf("body" to mockResponse)

        val header = mapOf("kid" to "did:example:123456789#keys-1")
        val result = resolver.resolveKey(header)

        assertEquals("mockPublicKey123", result )

    }


    @Test
    fun `should throw exception when kid is missing` (){
        every { NetworkManagerClient.sendHTTPRequest(any(), any()) } returns mapOf("body" to "mockResponse")

        val exception = assertThrows(JWTVerificationException.KidExtractionFailed::class.java) { resolver.resolveKey(emptyMap()) }
        assertEquals(
            "KID extraction from DID document failed",
            exception.message
        )
    }

    @Test
    fun `should throw exception when public key extraction fails`(){
        val mockResponse = """{
            "didDocument": {
                "verificationMethod": []
            }
        }"""

        every { NetworkManagerClient.sendHTTPRequest(any(), any()) } returns mapOf("body" to mockResponse)

        val header = mapOf("kid" to "did:example:123456789#keys-1")

        val exception = assertThrows(JWTVerificationException.PublicKeyExtractionFailed::class.java) { resolver.resolveKey(header) }
        assertEquals(
            "Public key extraction failed",
            exception.message
        )
    }

}

