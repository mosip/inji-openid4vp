package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.constants.ClientIdScheme.DID
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.didUrl
import io.mosip.openID4VP.testData.jws
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import org.junit.jupiter.api.Test
import java.security.PublicKey
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

    @Test
    fun `extractPublicKey should call DidPublicKeyResolver with correct values`() {
        val testKid = "test-key"

        val resolver = mockk<DidPublicKeyResolver>()
        val mockPublicKey = mockk<PublicKey>()
        every { resolver.resolve(didUrl, testKid) } returns mockPublicKey

        mockkConstructor(DidPublicKeyResolver::class)
        every { anyConstructed<DidPublicKeyResolver>().resolve(any(), any()) } answers {
            resolver.resolve(firstArg(), secondArg())
        }

        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            walletMetadata,
            setResponseUri,
            walletNonce
        )

        val publicKey = handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, testKid)

        assertEquals(mockPublicKey, publicKey)
        verify { resolver.resolve(didUrl, testKid) }

        unmockkConstructor(DidPublicKeyResolver::class)
    }

}
