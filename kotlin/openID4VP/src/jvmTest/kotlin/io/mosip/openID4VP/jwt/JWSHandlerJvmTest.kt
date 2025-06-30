package io.mosip.openID4VP.jwt

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.jwt.jws.createMockJws
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import io.mosip.openID4VP.testData.JWSUtil
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtHeader
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtPayload
import io.mosip.openID4VP.testData.assertDoesNotThrow
import kotlin.test.*

class JWSHandlerTest {
    private val publicKeyResolver = mockk<PublicKeyResolver>()


    @AfterTest
    fun tearDown() {
        clearAllMocks()
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
    fun `verify should throw exception with invalid signature`() {
        val publicKey = "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4="
        val jwt = JWSUtil.createJWS(jwtPayload, false, jwtHeader)

        every { publicKeyResolver.resolveKey(any()) } returns publicKey

        val exception = assertFailsWith<Exception> {
            JWSHandler(jwt, publicKeyResolver).verify()
        }

        assertEquals("JWS signature verification failed", exception.message)
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
    @Test
    fun `verify should pass with valid signature`() {
        val publicKey = "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4="
        val jwt =JWSUtil.createJWS(jwtPayload, true, jwtHeader)
        every { publicKeyResolver.resolveKey(any()) } returns publicKey

        assertDoesNotThrow { JWSHandler(jwt, publicKeyResolver).verify() }
    }


}