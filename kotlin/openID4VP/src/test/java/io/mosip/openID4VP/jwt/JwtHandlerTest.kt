package io.mosip.openID4VP.jwt

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mosip.openID4VP.jwt.keyResolver.KeyResolver
import io.mosip.openID4VP.testData.JWTUtil
import io.mosip.openID4VP.testData.JWTUtil.Companion.jwtHeader
import io.mosip.openID4VP.testData.JWTUtil.Companion.jwtPayload
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertThrows


class JwtHandlerTest {

    private val keyResolver = mockk<KeyResolver>()

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
        val jwt =JWTUtil.createJWT(jwtPayload, true, jwtHeader)
        every { keyResolver.resolveKey(any()) } returns publicKey

        val jwtHandler = JwtHandler(jwt, keyResolver)

        assertDoesNotThrow { jwtHandler.verify() }
    }

    @Test
    fun `verify should throw exception with invalid public key`() {
        val publicKey = "invalidPublicKeyBase64"
        val jwt =JWTUtil.createJWT(jwtPayload, true, jwtHeader)
        every { keyResolver.resolveKey(any()) } returns publicKey

        val jwtHandler = JwtHandler(jwt, keyResolver)

        val exception = assertThrows(Exception::class.java) { jwtHandler.verify() }

        assertEquals(
            "An unexpected exception occurred: exception type: VerificationFailure",
            exception.message
        )
    }

    @Test
    fun `verify should throw exception with invalid signature`() {
        val publicKey = "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4="
        val jwt =JWTUtil.createJWT(jwtPayload, false, jwtHeader)
        every { keyResolver.resolveKey(any()) } returns publicKey

        val jwtHandler = JwtHandler(jwt, keyResolver)

        val exception = assertThrows(Exception::class.java) { jwtHandler.verify() }

        assertEquals(
            "JWT signature verification failed",
            exception.message
        )
    }
}

