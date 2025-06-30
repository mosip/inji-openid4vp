package io.mosip.openID4VP.common

import android.util.Base64
import android.util.Base64.encodeToString
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

class EncoderTest {

    @BeforeTest
    fun setUp() {
        mockkStatic(Base64::class)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should encode the content to base64 url successfully with API lesser than Version O`() {
        every {
            encodeToString(
                "hello world".toByteArray(),
                any()
            )
        } returns "aGVsbG8gd29ybGQ="

        val encodedData = encodeToBase64Url("hello world".toByteArray())

        assertEquals("aGVsbG8gd29ybGQ=", encodedData)
    }
}
