package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.testData.*
import okhttp3.Headers
import io.mockk.*
import kotlin.test.*

class PreRegisteredSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletMetadata: WalletMetadata
    private val setResponseUri: (String) -> Unit = mockk(relaxed = true)
    private val validClientId = "mock-client"

    @BeforeTest
    fun setup() {

        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to validClientId,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to responseUrl,
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
            CLIENT_METADATA.value to clientMetadataString
        )

        walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf("jwt_vp" to VPFormatSupported(listOf("ES256"))),
            clientIdSchemesSupported = listOf("pre-registered")
        )
    }

    @Test
    fun `validateClientId should pass when client ID is trusted and validation is enabled`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        try {
            handler.validateClientId()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateClientId should skip validation when shouldValidateClient is false`() {
        authorizationRequestParameters[CLIENT_ID.value] = "untrusted-client-id"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, false, setResponseUri
        )

        try {
            handler.validateClientId()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateClientId should throw exception when client ID is not trusted`() {
        authorizationRequestParameters[CLIENT_ID.value] = "untrusted-client-id"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        val exception = assertFailsWith<Exception> {
            handler.validateClientId()
        }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `validateRequestUriResponse should accept valid JSON response`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", ContentType.APPLICATION_JSON.value)
            .build()

        val responseBody = """{"client_id":"$validClientId","response_uri":"$responseUrl"}"""
        val requestUriResponse = mapOf("header" to headers, "body" to responseBody)

        try {
            handler.validateRequestUriResponse(requestUriResponse)
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateRequestUriResponse should throw exception for invalid content type`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", "application/jwt")
            .build()

        val responseBody = """{"client_id":"$validClientId","response_uri":"$responseUrl"}"""
        val requestUriResponse = mapOf("header" to headers, "body" to responseBody)

        val exception = assertFailsWith<Exception> {
            handler.validateRequestUriResponse(requestUriResponse)
        }
        assertTrue(exception.message?.contains("Authorization Request must not be signed") == true)
    }

    @Test
    fun `process should return wallet metadata with null requestObjectSigningAlgValuesSupported`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        val processedMetadata = handler.process(walletMetadata.copy(
            requestObjectSigningAlgValuesSupported = listOf("ES256")
        ))

        assertNull(processedMetadata.requestObjectSigningAlgValuesSupported)
    }

    @Test
    fun `getHeadersForAuthorizationRequestUri should return correct headers`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        val headers = handler.getHeadersForAuthorizationRequestUri()

        assertEquals(ContentType.APPLICATION_FORM_URL_ENCODED.value, headers["content-type"])
        assertEquals(ContentType.APPLICATION_JSON.value, headers["accept"])
    }

    @Test
    fun `validateAndParseRequestFields should pass for trusted client with valid response URI`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when response URI is not trusted`() {
        authorizationRequestParameters[RESPONSE_URI.value] = "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        val exception = assertFailsWith<Exception> {
            handler.validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `validateAndParseRequestFields should skip validation when shouldValidateClient is false`() {
        authorizationRequestParameters[RESPONSE_URI.value] = "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, false, setResponseUri
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }
}
