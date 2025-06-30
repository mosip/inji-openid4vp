package io.mosip.openID4VP.jwt.jws

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import io.mosip.openID4VP.testData.JWSUtil
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtHeader
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtPayload
import java.util.Base64
import kotlin.test.*

class JWSHandlerTest {

    private val publicKeyResolver = mockk<PublicKeyResolver>()


    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }



    @Test
    fun `verify should throw exception with invalid public key`() {
        val publicKey = "invalidPublicKeyBase64"
        val jwt = JWSUtil.createJWS(jwtPayload, true, jwtHeader)
        every { publicKeyResolver.resolveKey(any()) } returns publicKey

        val exception = assertFailsWith<Exception> {
            JWSHandler(jwt, publicKeyResolver).verify()
        }
        assertTrue(exception.message!!.contains("An unexpected exception occurred during verification"))
    }


}

fun createMockJws(): String {
    val header = Base64.getUrlEncoder().encodeToString(
        """{"alg":"EdDSA","typ":"JWT"}""".toByteArray()
    )
    val payload = Base64.getUrlEncoder().encodeToString(
        """{"sub":"1234567890","name":"John Doe"}""".toByteArray()
    )
    val signature = Base64.getUrlEncoder().encodeToString("mockSignature".toByteArray())
    return "$header.$payload.$signature"
}
