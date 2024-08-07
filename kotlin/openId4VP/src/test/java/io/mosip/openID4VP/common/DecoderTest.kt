package io.mosip.openID4VP.common

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DecoderTest {

    @Test
    fun `should throw InvalidInputException for empty input`() {
        val encodedData = ""
        val expectedValue = "Invalid Input: encoded data value cannot be empty or null"

        val invalidInputException =
            assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                Decoder.decodeBase64ToString(encodedData)
            }

        assertEquals(expectedValue, invalidInputException.message)
    }

    @Test
    fun `should decode valid Base64 string`() {
        val encodedData = "SGVsbG8gV29ybGQ="
        val expectedDecodedString = "Hello World"

        val decodedString = Decoder.decodeBase64ToString(encodedData)

        assertEquals(expectedDecodedString, decodedString)
    }
}