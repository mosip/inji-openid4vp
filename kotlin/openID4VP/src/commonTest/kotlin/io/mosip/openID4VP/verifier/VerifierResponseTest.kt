package io.mosip.openID4VP.verifier

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class VerifierResponseTest {
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

    @Test
    fun `body returns responseBody value`() {
        val response = VerifierResponse(
            statusCode = 200,
            redirectUri = null,
            additionalParams = null,
            headers = emptyMap(),
            responseBody = "actual body"
        )
        assertEquals("actual body", response.body())
    }

    @Test
    fun `toString returns expected string`() {
        val response = VerifierResponse(
            statusCode = 201,
            redirectUri = "https://redirect.com",
            additionalParams = "{\"foo\":\"bar\"}",
            headers = mapOf("Content-Type" to listOf("application/json")),
            responseBody = "ignored"
        )
        val expected = "VerifierResponse(statusCode=201, redirectUri=https://redirect.com, additionalParams={\"foo\":\"bar\"}, headers={Content-Type=[application/json]})"
        assertEquals(expected, response.toString())
    }
}
