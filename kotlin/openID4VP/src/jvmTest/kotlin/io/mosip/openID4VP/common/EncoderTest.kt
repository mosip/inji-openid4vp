package io.mosip.openID4VP.common

import io.mockk.clearAllMocks
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals

class EncoderTest {



    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should encode the content to base64 url successfully`() {
        val encodedContent = encodeToBase64Url("hello world".toByteArray())
        assertEquals("aGVsbG8gd29ybGQ=", encodedContent)
    }

    @Test
    fun `should handle empty byte array properly`() {
        val encodedContent = encodeToBase64Url(ByteArray(0))
        assertEquals("", encodedContent)
    }

    @Test
    fun `should handle special characters correctly during encoding`() {
        val specialChars = "!@#$%^&*()_+{}[]|\":<>?,./"
        val encodedContent = encodeToBase64Url(specialChars.toByteArray())
        val decodedContent = decodeBase64Data(encodedContent)
        assertEquals(specialChars, decodedContent.toString(Charsets.UTF_8))
    }
}
