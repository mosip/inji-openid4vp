package io.mosip.openID4VP.common

import android.util.Base64
import io.mockk.every
import io.mockk.mockkStatic
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DecoderTest {

    @BeforeTest
    fun setUp() {
        mockkStatic(Base64::class)

        every {
            Base64.decode(any<String>(), any<Int>())
        } answers {
            ByteArray(0)
        }
    }

    @Test
    fun `should decode base64 url safe content`() {
        val input = "aGVsbG8gd29ybGQ="
        val expectedOutput = "hello world"

        every {
            Base64.decode(input, Base64.DEFAULT or Base64.URL_SAFE)
        } answers {
            expectedOutput.toByteArray()
        }

        val result = decodeBase64Data(input)
        assertEquals(expectedOutput, result.toString(Charsets.UTF_8))
    }

    @Test
    fun `should handle url safe characters`() {
        val input = "aGVsbG8-d29ybGQ_"
        val expectedOutput = "hello>world?"

        every {
            Base64.decode(input, Base64.DEFAULT or Base64.URL_SAFE)
        } answers {
            expectedOutput.toByteArray()
        }

        val result = decodeBase64Data(input)
        assertEquals(expectedOutput, result.toString(Charsets.UTF_8))
    }

    @Test
    fun `should throw error for invalid base64`() {
        val input = "invalid%%base64"

        every {
            Base64.decode(input, Base64.DEFAULT or Base64.URL_SAFE)
        } throws IllegalArgumentException("Invalid base64")

        assertFailsWith<IllegalArgumentException> {
            decodeBase64Data(input)
        }
    }
}
