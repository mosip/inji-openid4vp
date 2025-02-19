package io.mosip.openID4VP.common

import org.junit.Test
import org.junit.Assert.*
import io.mosip.openID4VP.networkManager.HTTP_METHOD

class UtilsTest {

    @Test
    fun `isValidUrl should return true for valid URL`() {
        val url = "https://example.com/path?query=value#fragment"
        assertTrue(isValidUrl(url))
    }

    @Test
    fun `isValidUrl should return false for invalid URL`() {


        val testUrls = listOf(
            "www.example.com",
            "http://example.com/space here",
            "http://",
            "https://example",
            "http://example.com/file%/name",
            "http://example.com:99999",
            "http:///example.com",
            "http://example.com/search?q=hello%20world#@fragment",
            "http://:8080",
            "",
            "https://example.com/invalid|character"
        )

        testUrls.forEach { url -> assertFalse(isValidUrl(url)) }
    }


    @Test
    fun `convertJsonToMap should correctly parse JSON string`() {
        val json = "{\"key\":\"value\"}"
        val result = convertJsonToMap(json)
        assertEquals("value", result["key"])
    }

    @Test
    fun `isJWT should return true for valid JWT`() {
        val jwt = "header.payload.signature"
        assertTrue(isJWT(jwt))
    }

    @Test
    fun `isJWT should return false for invalid JWT`() {
        val jwt = "invalid.jwt"
        assertFalse(isJWT(jwt))
    }

    @Test
    fun `determineHttpMethod should return correct HTTP method`() {
        assertEquals(HTTP_METHOD.GET, determineHttpMethod("get"))
        assertEquals(HTTP_METHOD.POST, determineHttpMethod("post"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `determineHttpMethod should throw exception for unsupported method`() {
        determineHttpMethod("put")
    }

    @Test
    fun `makeBase64Standard should standardize base64 string`() {
        val input = "dGVzdA"
        val expected = "dGVzdA=="
        assertEquals(expected, makeBase64Standard(input))
    }

    @Test
    fun `getStringValue should return correct string value from map`() {
        val map = mapOf("key" to "value")
        assertEquals("value", getStringValue(map, "key"))
        assertNull(getStringValue(map, "nonexistent"))
    }
}
