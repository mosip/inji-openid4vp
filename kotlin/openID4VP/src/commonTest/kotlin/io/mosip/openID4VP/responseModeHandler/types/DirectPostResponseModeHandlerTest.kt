package io.mosip.openID4VP.responseModeHandler.types

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import io.mosip.openID4VP.authorizationResponse.toJsonEncodedMap
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.authorizationResponse
import kotlin.test.*

class DirectPostResponseModeHandlerTest {

    @BeforeTest
    fun setUp() {
        mockkObject(NetworkManagerClient)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `validate should not throw any exception`() {
        val handler = DirectPostResponseModeHandler()
        handler.validate(null, null, false)
        // No exception means pass
    }

    @Test
    fun `sendAuthorizationResponse should send request and return response body`() {
        val handler = DirectPostResponseModeHandler()
        val responseUri = "https://example.com/response"
        val walletNonce = "test-nonce"
        val expectedResponse = "Response received"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to expectedResponse)

        val actualResponse = handler.sendAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            responseUri,
            authorizationResponse,
            walletNonce
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = responseUri,
                method = HttpMethod.POST,
                bodyParams = authorizationResponse.toJsonEncodedMap(),
                headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
            )
        }
        assertEquals(expectedResponse, actualResponse)
    }

    @Test
    fun `sendAuthorizationResponse should handle network errors`() {
        val handler = DirectPostResponseModeHandler()
        val responseUri = "https://example.com/response"
        val walletNonce = "test-nonce"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } throws java.io.IOException("Network error")

        val exception = assertFailsWith<java.io.IOException> {
            handler.sendAuthorizationResponse(
                authorizationRequestForResponseModeJWT,
                responseUri,
                authorizationResponse,
                walletNonce
            )
        }

        assertEquals("Network error", exception.message)
    }

    @Test
    fun `sendAuthorizationResponse should handle empty response`() {
        val handler = DirectPostResponseModeHandler()
        val responseUri = "https://example.com/response"
        val walletNonce = "test-nonce"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "")

        val actualResponse = handler.sendAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            responseUri,
            authorizationResponse,
            walletNonce
        )

        assertEquals("", actualResponse)
    }
}
