package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types


import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.clientMetadata.parseAndValidateClientMetadata
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.parseAndValidatePresentationDefinition
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.exceptions.Exceptions.*
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.responseUrl
import okhttp3.Headers
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Assertions.*

class RedirectUriSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletMetadata: WalletMetadata
    private val setResponseUri: (String) -> Unit = mockk(relaxed = true)

    @Before
    fun setup() {
        mockkObject(Logger)
        every { Logger.error(any(), any(), any()) } answers {  }

        // Client ID is set to response URI for redirect_uri scheme
        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to responseUrl,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to responseUrl,
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
            CLIENT_METADATA.value to clientMetadataString,
            CLIENT_ID_SCHEME.value to "redirect_uri"
        )

        walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf("jwt_vp" to VPFormatSupported(listOf("ES256"))),
            clientIdSchemesSupported = listOf("redirect_uri"),
            requestObjectSigningAlgValuesSupported = listOf("ES256", "RS256")
        )
    }

    @Test
    fun `validateRequestUriResponse should succeed with valid JSON content type`() {
        // Arrange
        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", ContentType.APPLICATION_JSON.value)
            .build()

        val requestUriResponse = mapOf(
            "header" to headers,
            "body" to """
                {
                    "client_id": "$responseUrl",
                    "response_type": "vp_token",
                    "response_uri": "$responseUrl",
                    "presentation_definition": $presentationDefinitionString,
                    "response_mode": "direct_post",
                    "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                    "client_id_scheme": "redirect_uri"
                }
            """.trimIndent()
        )

        // Act & Assert
        assertDoesNotThrow { handler.validateRequestUriResponse(requestUriResponse) }
    }

    @Test
    fun `validateRequestUriResponse should handle empty request URI response`() {
        // Arrange
        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        // Act & Assert
        assertDoesNotThrow { handler.validateRequestUriResponse(emptyMap()) }
    }

    @Test
    fun `validateRequestUriResponse should throw exception with invalid content type`() {
        // Arrange
        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", ContentType.APPLICATION_JWT.value)
            .build()

        val requestUriResponse = mapOf(
            "header" to headers,
            "body" to """
                {
                    "client_id": "https://example.com/response",
                    "response_type": "vp_token",
                    "response_uri": "https://example.com/response"
                }
            """.trimIndent()
        )

        // Act & Assert
        val exception = assertThrows<InvalidData> { handler.validateRequestUriResponse(requestUriResponse) }
        assertTrue(exception.message?.contains("Authorization Request must not be signed") == true)
    }

    @Test
    fun `process should return wallet metadata with requestObjectSigningAlgValuesSupported set to null`() {
        // Arrange
        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        // Act
        val result = handler.process(walletMetadata)

        // Assert
        assertNull(result.requestObjectSigningAlgValuesSupported)
    }

    @Test
    fun `getHeadersForAuthorizationRequestUri should return correct headers`() {
        // Arrange
        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        // Act
        val headers = handler.getHeadersForAuthorizationRequestUri()

        // Assert
        assertEquals(ContentType.APPLICATION_FORM_URL_ENCODED.value, headers["content-type"])
        assertEquals(ContentType.APPLICATION_JSON.value, headers["accept"])
    }

    @Test
    fun `validateAndParseRequestFields should succeed with valid direct_post response mode`() {
        // Arrange
        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        // Act & Assert
        assertDoesNotThrow { handler.validateAndParseRequestFields() }
    }

    @Test
    fun `validateAndParseRequestFields should succeed with direct_post_jwt response mode`() {
        // Arrange
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = "direct_post.jwt"

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri
        )

        // Act & Assert
        assertDoesNotThrow { handler.validateAndParseRequestFields() }
    }

    @Test
    fun `validateAndParseRequestFields should throw exception with unsupported response mode`() {
        // Arrange
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = "unsupported_mode"

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri
        )

        // Act & Assert
        val exception = assertThrows<InvalidData> { handler.validateAndParseRequestFields() }
        assertTrue(exception.message?.contains("Given response_mode is not supported") == true)
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when response_mode is missing`() {
        mockkStatic("io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataUtilKt")
        every {
            parseAndValidateClientMetadata(any(), any(), any())
        }  just runs

        // Mock the PresentationDefinitionUtil function - this is what's causing the NPE
        mockkStatic("io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionUtilKt")
        every {
            parseAndValidatePresentationDefinition(any(), any())
        } just runs

        val modifiedParams = authorizationRequestParameters.toMutableMap().apply {
            remove(RESPONSE_MODE.value)
        }

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri
        )

        val exception = assertThrows<MissingInput> { handler.validateAndParseRequestFields() }
        assertTrue(exception.message?.contains("response_mode") == true)

        unmockkStatic("io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataUtilKt")
    }


    @Test
    fun `validateAndParseRequestFields should throw exception when REDIRECT_URI is present`() {
        // Arrange
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[REDIRECT_URI.value] = "https://example.com/redirect"

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri
        )

        // Act & Assert
        val exception = assertThrows<InvalidData> { handler.validateAndParseRequestFields() }
        assertTrue(exception.message?.contains("redirect_uri should not be present") == true)
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when RESPONSE_URI is missing`() {
        // Arrange
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams.remove(RESPONSE_URI.value)

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri
        )

        // Act & Assert
        val exception = assertThrows<MissingInput> { handler.validateAndParseRequestFields() }
        assertTrue(exception.message?.contains("response_uri") == true)
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when RESPONSE_URI doesn't match CLIENT_ID`() {
        // Arrange
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_URI.value] = "https://different-domain.com/response"

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri
        )

        // Act & Assert
        val exception = assertThrows<InvalidData> { handler.validateAndParseRequestFields() }
        assertTrue(exception.message?.contains("response_uri should be equal to client_id") == true)
    }
}