package io.mosip.openID4VP.jwt

import io.mockk.clearAllMocks
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.jwt.jws.createMockJws
import io.mosip.openID4VP.testData.JWSUtil
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtHeader
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtPayload
import io.mosip.openID4VP.testData.assertDoesNotThrow
import io.mosip.openID4VP.testData.didUrl
import io.mosip.vercred.vcverifier.publicKey.types.did.DidPublicKeyResolver
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class JWSHandlerTest {
    private val publicKeyResolver = DidPublicKeyResolver()


    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should extract header successfully`() {
        val mockJws = createMockJws()
        val result =
            JWSHandler.extractDataJsonFromJws(mockJws, JWSHandler.JwsPart.HEADER)
        assertNotNull(result)
        assertTrue(result.isNotEmpty())
    }

    @Test
    fun `verify should throw exception with invalid signature`() {
        val jwt = JWSUtil.createJWS(jwtPayload, false, jwtHeader)

        val exception = assertFailsWith<Exception> {
            JWSHandler.verify(
                jwt,
                publicKeyResolver,
                didUrl
            )
        }

        assertEquals("JWS signature verification failed", exception.message)
    }

    @Test
    fun `should extract payload successfully`() {
        val mockJws = createMockJws()
        val result = JWSHandler.extractDataJsonFromJws(mockJws, JWSHandler.JwsPart.PAYLOAD)
        assertNotNull(result)
        assertTrue(result.isNotEmpty())
    }

    @Test
    fun `verify should pass with valid signature`() {
        val jwt = JWSUtil.createJWS(jwtPayload, true, jwtHeader)

        assertDoesNotThrow {
            JWSHandler.verify(
                jwt,
                publicKeyResolver,
                didUrl
            )
        }
    }
}