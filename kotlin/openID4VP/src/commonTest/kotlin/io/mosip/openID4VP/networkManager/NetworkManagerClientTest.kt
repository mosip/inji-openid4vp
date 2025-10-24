package io.mosip.openID4VP.networkManager

import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NetworkManagerClientTest {
    private lateinit var mockWebServer: MockWebServer

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()
    }

    @After
    fun tearDown() {
        mockWebServer.shutdown()
    }

    @Test
    fun `should return successful response for GET`() {
        val expectedBody = "OK"
        mockWebServer.enqueue(MockResponse().setResponseCode(200).setBody(expectedBody))
        val url = mockWebServer.url("/test-get").toString()
        val method = HttpMethod.GET
        val response = sendHTTPRequest(url, method)
        assertTrue(response.statusCode == 200)
        assertEquals(expectedBody, response.body)
    }

    @Test
    fun `should return successful response for POST`() {
        val expectedBody = "Created"
        mockWebServer.enqueue(MockResponse().setResponseCode(201).setBody(expectedBody))
        val url = mockWebServer.url("/test-post").toString()
        val method = HttpMethod.POST
        val bodyParams = mapOf("key" to "value")
        val response = sendHTTPRequest(url, method, bodyParams)
        assertTrue(response.statusCode == 201)
        assertEquals(expectedBody, response.body)
    }

    @Test
    fun `should handle network error`() {
        mockWebServer.shutdown() // Simulate network error
        val url = mockWebServer.url("/test-error").toString()
        val method = HttpMethod.GET
        assertFailsWith<Exception> {
            sendHTTPRequest(url, method)
        }
    }
}
