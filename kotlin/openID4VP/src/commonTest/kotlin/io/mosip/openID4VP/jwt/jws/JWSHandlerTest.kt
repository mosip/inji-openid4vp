package io.mosip.openID4VP.jwt.jws

import io.mockk.clearAllMocks
import io.mockk.mockk
import io.mosip.openID4VP.testData.JWSUtil
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtHeader
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtPayload
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolver
import org.junit.jupiter.api.Test
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
        val publicKey = mockk<java.security.PublicKey>()
        val jwt = JWSUtil.createJWS(jwtPayload, true, jwtHeader)

        val exception = assertFailsWith<Exception> {
            JWSHandler.verify(
                jwt,
                publicKey,
            )
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
