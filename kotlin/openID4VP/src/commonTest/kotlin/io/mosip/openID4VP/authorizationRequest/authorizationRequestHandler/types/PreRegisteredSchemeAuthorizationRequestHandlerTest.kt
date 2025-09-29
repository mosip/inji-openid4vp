package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.common.resolveJwksFromUri
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.HttpMethod.GET
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.*
import io.mosip.openID4VP.testData.JWSUtil.Companion.buildTestJwk
import org.junit.jupiter.api.Test
import kotlin.test.*

class PreRegisteredSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletMetadata: WalletMetadata
    private val setResponseUri: (String) -> Unit = mockk(relaxed = true)
    private val validClientId = "mock-client"
    val clientMetadata = ClientMetadata(
        clientName = "mock-client",
        vpFormats = mapOf("ldp_vc" to mapOf("signing_alg" to listOf("ES256"))),
    )
    private var trustedVerifiers: MutableList<Verifier> = mutableListOf(
        Verifier(
            "mock-client", listOf(
                "https://mock-verifier.com/response-uri", "https://verifier.env2.com/responseUri"
            )
        )
    )

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
        )

        walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to VPFormatSupported(listOf("ES256"))),
            clientIdSchemesSupported = listOf(ClientIdScheme.PRE_REGISTERED)
        )

        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/.well-known/jwks.json",
                GET
            )
        } returns mapOf("body" to jwkSet)
    }

    @Test
    fun `validateClientId should pass when client ID is trusted and validation is enabled`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            true,
            setResponseUri,
            walletNonce
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
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            false,
            setResponseUri,
            walletNonce
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
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            true,
            setResponseUri,
            walletNonce
        )

        val exception = assertFailsWith<Exception> {
            handler.validateClientId()
        }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `process should return wallet metadata with null requestObjectSigningAlgValuesSupported`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            true,
            setResponseUri,
            walletNonce
        )

        val processedMetadata = handler.process(
            walletMetadata.copy(
                requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA)
            )
        )

        assertNull(processedMetadata.requestObjectSigningAlgValuesSupported)
    }


    @Test
    fun `validateAndParseRequestFields should pass for trusted client with valid response URI`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            true,
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateAndParseRequestFields should not throw exception when client metadata of the pre-registered verifier is not known and its available in authorization request`() {
        val trustedVerifiersWithoutClientMetadata: List<Verifier> = listOf(
            Verifier(
                "mock-client",
                listOf(
                    "https://mock-verifier.com/response-uri",
                    "https://verifier.env2.com/responseUri"
                ),
            )
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiersWithoutClientMetadata,
            (authorizationRequestParameters + mapOf(
                CLIENT_METADATA.value to clientMetadataString
            )) as MutableMap<String, Any>,
            walletMetadata,
            true,
            setResponseUri,
            walletNonce
        )

        assertDoesNotThrow {
            handler.validateAndParseRequestFields()
        }
    }


    @Test
    fun `validateAndParseRequestFields should update authorization request with client_metadata if its available in the related pre-registered verifier`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            true,
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateAndParseRequestFields()

            assertEquals(
                handler.authorizationRequestParameters[CLIENT_METADATA.value],
                clientMetadata
            )
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when response URI is not trusted`() {
        authorizationRequestParameters[RESPONSE_URI.value] =
            "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            true,
            setResponseUri,
            walletNonce
        )

        val exception = assertFailsWith<Exception> {
            handler.validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `validateAndParseRequestFields should skip validation when shouldValidateClient is false`() {
        authorizationRequestParameters[RESPONSE_URI.value] =
            "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            walletMetadata,
            false,
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `should extract key successfully when kid is present`() {

        val testKid = "test-key"

        val verifier = Verifier(
            clientId = "test-client",
            responseUris = listOf("https://example.com/callback"),
            jwksUri = "https://example.com/.well-known/jwks.json"
        )
        trustedVerifiers.add(verifier)

        authorizationRequestParameters[CLIENT_ID.value] = "test-client"

        mockkStatic("io.mosip.openID4VP.common.UtilsKt")

        val jwkList = listOf(
            Jwk(
                kty = "OKP",
                crv = "Ed25519",
                use = "sig",
                x = "-Fy3lMapzR3wpaYNCFq29GDEn_NoR3pBsc511q1Cxqw",
                alg = "EdDSA",
                kid = testKid
            )
        )
        every { resolveJwksFromUri(any(), any()) } returns Jwks(jwkList)

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers = trustedVerifiers,
            authorizationRequestParameters = authorizationRequestParameters,
            walletMetadata = null,
            shouldValidateClient = false,
            setResponseUri,
            walletNonce
        )

        val publicKey = handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, testKid)

        assertNotNull(publicKey)
        assertEquals("Ed25519", publicKey.algorithm)
        assertTrue(publicKey.encoded.isNotEmpty())
    }


    @Test
    fun `should throw when kid is present and not found in client metadata`() {
        val testKid = "some-other-key"
        val testJwk = buildTestJwk(kid = testKid)

        val verifier = Verifier(
            clientId = "test-client",
            responseUris = listOf("https://example.com/callback")
        )
        trustedVerifiers.add(verifier)
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers = trustedVerifiers,
            authorizationRequestParameters = authorizationRequestParameters,
            walletMetadata = null,
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, "non-existent")
        }

        assertTrue(ex.message.contains("Public key extraction failed for kid"))
    }

    @Test
    fun `should pick key by alg if no kid and one matching key present`() {
        val testJwk = buildTestJwk(kid = null)

        val verifier = Verifier(
            clientId = "test-client",
            responseUris = listOf("https://example.com/callback")
        )
        trustedVerifiers.add(verifier)
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers = trustedVerifiers,
            authorizationRequestParameters = authorizationRequestParameters,
            walletMetadata = null,
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val publicKey = handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, null)
        assertNotNull(publicKey)
    }

    @Test
    fun `should throw if multiple sig-use keys present and no kid`() {
        val key1 = buildTestJwk(kid = "k1")
        val key2 = buildTestJwk(kid = "k2")

        val verifier = Verifier(
            clientId = "test-client",
            responseUris = listOf("https://example.com/callback")
        )
        trustedVerifiers.add(verifier)
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers = trustedVerifiers,
            authorizationRequestParameters = authorizationRequestParameters,
            walletMetadata = null,
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, null)
        }

        assertTrue(ex.message!!.contains("Multiple ambiguous keys found for EdDSA with signature usage"))
    }

    @Test
    fun `should throw if no matching keys for alg`() {
        val key = buildTestJwk(kty = "RSA", crv = "") // non-EdDSA key

        val verifier = Verifier(
            clientId = "test-client",
            responseUris = listOf("https://example.com/callback"),
            jwksUri = "https://example.com/.well-known/jwks.json"
        )
        trustedVerifiers.add(verifier)
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers = trustedVerifiers,
            authorizationRequestParameters = authorizationRequestParameters,
            walletMetadata = null,
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, null)
        }

        assertTrue(ex.message!!.contains("No public key found for algorithm: EdDSA with signature usage"))
    }

    @Test
    fun `should throw if curve is unsupported in matching key`() {
        mockkObject(NetworkManagerClient)
        val verifier = Verifier(
            clientId = "test-client",
            responseUris = listOf("https://example.com/callback"),
            jwksUri = "https://example.com/.well-known/jwks.json"
        )
        every { NetworkManagerClient.sendHTTPRequest("https://example.com/.well-known/jwks.json", GET) } returns mapOf(
            "body" to """{"keys": [{
                "kty": "OKP",
                "use": "sig",
                "alg": "EdDSA",
                "crv": "XYZ",
                "x": "11qYAYdk9J6r9xWhG7f8z1FMvx6bAQJz2-LU8C5QWAc",
                }]}""".trimMargin()
        )
        trustedVerifiers.add(verifier)
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers = trustedVerifiers,
            authorizationRequestParameters = authorizationRequestParameters,
            walletMetadata = null,
            shouldValidateClient = false,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(RequestSigningAlgorithm.EdDSA, "test-kid")
        }
        assertTrue(ex.message!!.contains("Public key extraction failed - Curve - XYZ is not supported. Supported: Ed25519"))
    }

}

