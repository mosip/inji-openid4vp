package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import kotlin.test.Test
import kotlin.test.BeforeTest
import kotlin.test.assertFailsWith

class ClientIdSchemeBasedAuthorizationRequestHandlerTest {
    @BeforeTest
    fun setUp() {
        mockkObject(NetworkManagerClient)
    }

    @Test
    fun `should throw error when request uri returns non 2xx response`() {
        val mockHandler = object : ClientIdSchemeBasedAuthorizationRequestHandler(
            mutableMapOf(REQUEST_URI.value to "https://example.com/request"),
            null,
            {},
            "walletNonce"
        ) {
            override fun isRequestUriSupported() = true
            override fun isRequestObjectSupported() = false
            override fun clientIdScheme() = "test"
            override fun extractPublicKey(algorithm: RequestSigningAlgorithm, kid: String?) = throw NotImplementedError()
            override fun process(walletMetadata: WalletMetadata) = walletMetadata
        }

        // Mock sendHTTPRequest to return non-200 response
        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any(), any()
            )
        } returns NetworkResponse(400, """{"message":"error"}""", mapOf("Content-Type" to listOf("application/json")))


        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }
    }
}

