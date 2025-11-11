package io.mosip.openID4VP.verifier

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class VerifierResponseTest {
    @Test
    fun `composedBody returns additionalParams when redirectUri is null and additionalParams is not blank`() {
        val response = VerifierResponse(
            statusCode = 200,
            redirectUri = null,
            additionalParams = "{\"foo\":\"bar\"}",
            headers = emptyMap()
        )
        assertEquals("{\"foo\":\"bar\"}", response.composedBody())
    }

    @Test
    fun `composedBody returns empty string when both redirectUri and additionalParams are null`() {
        val response = VerifierResponse(
            statusCode = 200,
            redirectUri = null,
            additionalParams = null,
            headers = emptyMap()
        )
        assertEquals("", response.composedBody())
    }

    @Test
    fun `composedBody returns JSON with redirectUri when both redirectUri and additionalParams are present`() {
        val response = VerifierResponse(
            statusCode = 200,
            redirectUri = "https://redirect.com",
            additionalParams = "{\"foo\":\"bar\"}",
            headers = emptyMap()
        )
        val result = response.composedBody()
        val expected = "{\"foo\":\"bar\",\"redirect_uri\":\"https://redirect.com\"}"
        assertEquals(expected, result)
    }

    @Test
    fun `composedBody returns JSON with only redirectUri when additionalParams is blank`() {
        val response = VerifierResponse(
            statusCode = 200,
            redirectUri = "https://redirect.com",
            additionalParams = "",
            headers = emptyMap()
        )
        val result = response.composedBody()
        val expected = "{\"redirect_uri\":\"https://redirect.com\"}"
        assertEquals(expected, result)
    }

    @Test
    fun `composedBody returns additionalParams if additionalParams is not valid JSON and redirectUri is null`() {
        val response = VerifierResponse(
            statusCode = 200,
            redirectUri = null,
            additionalParams = "not a json",
            headers = emptyMap()
        )
        assertEquals("not a json", response.composedBody())
    }

    @Test
    fun `composedBody returns additionalParams if additionalParams is not valid JSON and redirectUri is present`() {
        val response = VerifierResponse(
            statusCode = 200,
            redirectUri = "https://redirect.com",
            additionalParams = "not a json",
            headers = emptyMap()
        )
        // Should return additionalParams as fallback
        assertEquals("not a json", response.composedBody())
    }

    @Test
    fun `isOk returns true for 2xx status codes`() {
        assertTrue(VerifierResponse(200, null, null, emptyMap()).isOk())
        assertTrue(VerifierResponse(299, null, null, emptyMap()).isOk())
    }

    @Test
    fun `isOk returns false for non-2xx status codes`() {
        assertFalse(VerifierResponse(199, null, null, emptyMap()).isOk())
        assertFalse(VerifierResponse(300, null, null, emptyMap()).isOk())
    }
}
