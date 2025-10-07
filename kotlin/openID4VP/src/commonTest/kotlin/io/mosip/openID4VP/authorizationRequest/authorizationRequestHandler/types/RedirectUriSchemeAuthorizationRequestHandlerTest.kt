package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.parseAndValidateClientMetadata
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.parseAndValidatePresentationDefinition
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.responseUrl
import org.junit.jupiter.api.Test
import kotlin.test.*

class RedirectUriSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletMetadata: WalletMetadata
    private val setResponseUri: (String) -> Unit = mockk(relaxed = true)
    val walletNonce = "VbRRB/LTxLiXmVNZuyMO8A=="

    @BeforeTest
    fun setup() {

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
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to VPFormatSupported(listOf("ES256"))),
            clientIdSchemesSupported = listOf(ClientIdScheme.REDIRECT_URI),
            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA)
        )
    }

    @Test
    fun `process should return wallet metadata with requestObjectSigningAlgValuesSupported set to null`() {
        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri, walletNonce
        )

        val result = handler.process(walletMetadata)

        assertNull(result.requestObjectSigningAlgValuesSupported)
    }

    @Test
    fun `validateAndParseRequestFields should succeed with valid direct_post response mode`() {
        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri, walletNonce
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateAndParseRequestFields should succeed with direct_post_jwt response mode`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = "direct_post.jwt"

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri, walletNonce
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateAndParseRequestFields should throw exception with unsupported response mode`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = "unsupported_mode"

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri, walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("Given response_mode is not supported") == true)
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when response_mode is missing`() {
        mockkStatic("io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataUtilKt")
        every {
            parseAndValidateClientMetadata(any(), any(), any())
        } just runs

        mockkStatic("io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionUtilKt")
        every {
            parseAndValidatePresentationDefinition(any(), any())
        } just runs

        val modifiedParams = authorizationRequestParameters.toMutableMap().apply {
            remove(RESPONSE_MODE.value)
        }

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri, walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("response_mode") == true)

        unmockkStatic("io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataUtilKt")
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when REDIRECT_URI is present`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[REDIRECT_URI.value] = "https://example.com/redirect"

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri, walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("redirect_uri should not be present") == true)
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when RESPONSE_URI is missing`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams.remove(RESPONSE_URI.value)

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri, walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("response_uri") == true)
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when RESPONSE_URI doesn't match CLIENT_ID`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_URI.value] = "https://different-domain.com/response"

        val handler = RedirectUriSchemeAuthorizationRequestHandler(
            modifiedParams, walletMetadata, setResponseUri, walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("response_uri should be equal to client_id") == true)
    }
}
