package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.constants.ClientIdScheme.DID
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.didUrl
import io.mosip.openID4VP.testData.jws
import io.mosip.openID4VP.testData.presentationDefinitionString
import okhttp3.Headers
import kotlin.test.*

class DidSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletMetadata: WalletMetadata
    private val setResponseUri: (String) -> Unit = mockk(relaxed = true)
    val walletNonce = "VbRRB/LTxLiXmVNZuyMO8A=="

    @BeforeTest
    fun setup() {


        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to didUrl,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to "https://example.com/response",
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
            CLIENT_METADATA.value to clientMetadataString
        )

        walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to VPFormatSupported(listOf("ES256"))),
            clientIdSchemesSupported = listOf(DID),
            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA)
        )

        mockkObject(JWSHandler)
        every { JWSHandler.extractDataJsonFromJws(jws,JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "ES256")
        every { JWSHandler.extractDataJsonFromJws(jws,JWSHandler.JwsPart.PAYLOAD) } returns authorizationRequestParameters
    }

    @Test
    fun `validateRequestUriResponse should succeed with valid JWS and content type`() {
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )
        val headers =
            Headers.Builder().add("content-type", ContentType.APPLICATION_JWT.value).build()
        val requestUriResponse = mapOf("header" to headers, "body" to jws)

        every {
            JWSHandler.verify(
                any(),
                any(),
                any()
            )
        } just runs

        try {
            handler.validateRequestUriResponse(requestUriResponse)
        } catch (e: Throwable) {
            fail("Expected no exception, but caught: ${e::class.simpleName} - ${e.message}")
        }

        verify { JWSHandler.extractDataJsonFromJws(jws, JWSHandler.JwsPart.HEADER) }
        verify { JWSHandler.extractDataJsonFromJws(jws, JWSHandler.JwsPart.PAYLOAD) }
    }

    @Test
    fun `validateRequestUriResponse should throw exception with invalid content type`() {
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )
        val headers =
            Headers.Builder().add("content-type", ContentType.APPLICATION_JSON.value).build()
        val requestUriResponse = mapOf("header" to headers, "body" to jws)

        val exception = assertFailsWith<Exception> {
            handler.validateRequestUriResponse(requestUriResponse)
        }
        assertTrue(exception.message?.contains("Authorization Request must be signed") == true)
    }

    @Test
    fun `validateRequestUriResponse should throw exception when body is not JWS`() {
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )
        val headers =
            Headers.Builder().add("content-type", ContentType.APPLICATION_JWT.value).build()
        val requestUriResponse = mapOf("header" to headers, "body" to "{\"client_id\":\"didUrl\"}")

        val exception = assertFailsWith<Exception> {
            handler.validateRequestUriResponse(requestUriResponse)
        }
        assertTrue(exception.message?.contains("Authorization Request must be signed") == true)
    }

    @Test
    fun `validateRequestUriResponse should throw exception when JWS verification fails`() {
        every { JWSHandler.verify(
            jws,
            any(),
            didUrl
        ) } throws Exception("Invalid signature")

        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )
        val headers =
            Headers.Builder().add("content-type", ContentType.APPLICATION_JWT.value).build()
        val requestUriResponse = mapOf("header" to headers, "body" to jws)

        assertFailsWith<Exception> {
            handler.validateRequestUriResponse(requestUriResponse)
        }
    }

    @Test
    fun `validateRequestUriResponse should throw exception when requestUriResponse is empty`() {
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validateRequestUriResponse(emptyMap())
        }
        assertEquals("Missing Input: request_uri param is required", exception.message)
    }

    @Test
    fun `validateRequestUriResponse should throw exception when signing algorithm is not supported`() {
        every { JWSHandler.verify(
            jws,
            any(),
            didUrl
        ) } just runs
        every { JWSHandler.extractDataJsonFromJws(jws,JWSHandler.JwsPart.HEADER) } returns mutableMapOf(
            "alg" to "HS256"
        )

        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )

        val field =
            handler.javaClass.superclass.getDeclaredField("shouldValidateWithWalletMetadata")
        field.isAccessible = true
        field.set(handler, true)

        val headers =
            Headers.Builder().add("content-type", ContentType.APPLICATION_JWT.value).build()
        val requestUriResponse = mapOf("header" to headers, "body" to jws)

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.validateRequestUriResponse(requestUriResponse)
        }
        assertEquals("request_object_signing_alg is not support by wallet", exception.message)
    }

    @Test
    fun `process should return wallet metadata when requestObjectSigningAlgValuesSupported is valid`() {
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )

        val result = handler.process(walletMetadata)

        assertEquals(walletMetadata, result)
        assertEquals(
            listOf(RequestSigningAlgorithm.EdDSA),
            result.requestObjectSigningAlgValuesSupported
        )
    }

    @Test
    fun `process should throw exception when requestObjectSigningAlgValuesSupported is empty`() {
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )

        val invalidWalletMetadata =
            walletMetadata.copy(requestObjectSigningAlgValuesSupported = emptyList())

        val exception = assertFailsWith<Exception> {
            handler.process(invalidWalletMetadata)
        }
        assertTrue(exception.message?.contains("request_object_signing_alg_values_supported is not present") == true)
    }

    @Test
    fun `getHeadersForAuthorizationRequestUri should return correct headers`() {
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )

        val headers = handler.getHeadersForAuthorizationRequestUri()

        assertEquals(ContentType.APPLICATION_FORM_URL_ENCODED.value, headers["content-type"])
        assertEquals(ContentType.APPLICATION_JWT.value, headers["accept"])
    }
}
