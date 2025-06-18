package io.mosip.openID4VP.jwt.jws

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import io.mosip.openID4VP.testData.JWSUtil
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtHeader
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtPayload
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import java.util.Base64


class JWSHandlerTest {

    private val publicKeyResolver = mockk<PublicKeyResolver>()

    @Before
    fun setUp() {
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
    fun `verify should pass with valid signature`() {
        val publicKey = "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4="
        val jwt =JWSUtil.createJWS(jwtPayload, true, jwtHeader)
        every { publicKeyResolver.resolveKey(any()) } returns publicKey

        assertDoesNotThrow { JWSHandler(jwt, publicKeyResolver).verify() }
    }

    @Test
    fun `verify should throw exception with invalid public key`() {
        val publicKey = "invalidPublicKeyBase64"
        val jwt =JWSUtil.createJWS(jwtPayload, true, jwtHeader)
        every { publicKeyResolver.resolveKey(any()) } returns publicKey
        val exception =
            assertThrows(Exception::class.java) { JWSHandler(jwt, publicKeyResolver).verify() }
        assertTrue(exception.message!!.contains("An unexpected exception occurred during verification"))
    }

    @Test
    fun `verify should throw exception with invalid signature`() {
        val publicKey = "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4="
        val jwt =JWSUtil.createJWS(jwtPayload, false, jwtHeader)
        every { publicKeyResolver.resolveKey(any()) } returns publicKey

        val exception =
            assertThrows(Exception::class.java) { JWSHandler(jwt, publicKeyResolver).verify() }

        assertEquals(
            "invalid_request: JWS signature verification failed",
            exception.message
        )
    }

    @Test
    fun `should extract header successfully`() {
        val mockJws = createMockJws()
        val result =
            JWSHandler(mockJws, publicKeyResolver).extractDataJsonFromJws(JWSHandler.JwsPart.HEADER)
        assertNotNull(result)
        assertTrue(result.isNotEmpty())
    }

    @Test
    fun `should extract payload successfully`() {
        val mockJws = createMockJws()
        val result = JWSHandler(
            mockJws,
            publicKeyResolver
        ).extractDataJsonFromJws(JWSHandler.JwsPart.PAYLOAD)
        assertNotNull(result)
        assertTrue(result.isNotEmpty())
    }
}

private fun createMockJws(): String {
    val header = Base64.getUrlEncoder().encodeToString(
        """{"alg":"EdDSA","typ":"JWT"}""".toByteArray()
    )
    val payload = Base64.getUrlEncoder().encodeToString(
        """{"sub":"1234567890","name":"John Doe"}""".toByteArray()
    )
    val signature = Base64.getUrlEncoder().encodeToString("mockSignature".toByteArray())
    return "$header.$payload.$signature"
}

