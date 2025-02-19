package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.Headers
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class AuthorizationResponseTest {
    private lateinit var openID4VP: OpenID4VP
    private val selectedCredentialsList = mapOf(
        "456" to listOf(
            """{"format":"ldp_vc","verifiableCredential":{"credential":{"issuanceDate":"2024-08-02T16:04:35.304Z","credentialSubject":{"face":"data:image/jpeg;base64,/9j/goKCyuig","dateOfBirth":"2000/01/01","id":"did:jwk:eyJr80435=","UIN":"9012378996","email":"mockuser@gmail.com"},"id":"https://domain.net/credentials/12345-87435","proof":{"type":"RsaSignature2018","created":"2024-04-14T16:04:35Z","proofPurpose":"assertionMethod","verificationMethod":"https://domain.net/.well-known/public-key.json","jws":"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ"},"type":["VerifiableCredential"],"@context":["https://www.w3.org/2018/credentials/v1","https://domain.net/.well-known/context.json",{"sec":"https://w3id.org/security#"}],"issuer":"https://domain.net/.well-known/issuer.json"}}}""",
            """{"verifiableCredential":{"credential":{"issuanceDate":"2024-08-12T18:03:35.304Z","credentialSubject":{"face":"data:image/jpeg;base64,/9j/goKCyuig","dateOfBirth":"2000/01/01","id":"did:jwk:eyJr80435=","UIN":"9012378996","email":"mockuser@gmail.com"},"id":"https://domain.net/credentials/12345-87435","proof":{"type":"RsaSignature2018","created":"2024-04-14T16:04:35Z","proofPurpose":"assertionMethod","verificationMethod":"https://domain.net/.well-known/public-key.json","jws":"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ"},"type":["VerifiableCredential"],"@context":["https://www.w3.org/2018/credentials/v1","https://domain.net/.well-known/context.json",{"sec":"https://w3id.org/security#"}],"issuer":"https://domain.net/.well-known/issuer.json"}}}"""
        ), "789" to listOf(
            """{"format":"ldp_vc","verifiableCredential":{"credential":{"issuanceDate":"2024-08-18T13:02:35.304Z","credentialSubject":{"face":"data:image/jpeg;base64,/9j/goKCyuig","dateOfBirth":"2000/01/01","id":"did:jwk:eyJr80435=","UIN":"9012378996","email":"mockuser@gmail.com"},"id":"https://domain.net/credentials/12345-87435","proof":{"type":"RsaSignature2018","created":"2024-04-14T16:04:35Z","proofPurpose":"assertionMethod","verificationMethod":"https://domain.net/.well-known/public-key.json","jws":"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ"},"type":["VerifiableCredential"],"@context":["https://www.w3.org/2018/credentials/v1","https://domain.net/.well-known/context.json",{"sec":"https://w3id.org/security#"}],"issuer":"https://domain.net/.well-known/issuer.json"}}}"""
        )
    )
    private val publicKey = """-----BEGIN RSA PUBLIC KEY-----
        MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E
        lDNkSfHIgBijphkgSXpVMduwWKidiFFtbqQHgKdr4vdiMKzTy8g0aTpD8T5xPImM
        CC6CUVgp4EZZHkFK3S2guLZAanXLju3WBD4FuBQTl08vP5MlsiseIIanOnTulUDR
        baGIYhONq2kN9UnLIXcv8QPIgroP/n76Ir39EwRd20E4jsNfEriZFthBZKQLNbTz
        GrsVMtpUbHPUlvACrTzXm5RQ1THHDYUa46KmxZfTCKWM2EppaoJlUj1psf3LdlOU
        MBAarn+3QUxYOMLu9vTLvqsk606WNbeuiHarY6lBAec1E6RXMIcVLKBqMy6NjMCK
        Va3ZFvn6/G9JI0U+S8Nn3XpH5nLnyAwim7+l9ZnmqeKTTcnE8oxEuGdP7+VvpyHE
        AF8jilspP0PuBLMNV4eNthKPKPfMvBbFtzLcizqXmSLPx8cOtrEOu+cEU6ckavAS
        XwPgM27JUjeBwwnAhS8lrN3SiJLYCCi1wXjgqFgESNTBhHq+/H5Mb2wxliJQmfzd
        BQOI7kr7ICohW8y2ivCBKGR3dB9j7l77C0o/5pzkHElESdR2f3q+nXfHds2NmoRU
        IGZojdVF+LrGiwRBRUvZMlSKUdsoYVAxz/a5ISGIrWCOd9PgDO5RNNUCAwEAAQ==
        -----END RSA PUBLIC KEY-----"""
    private lateinit var presentationDefinition: String
    private lateinit var clientMetadata: String
    private lateinit var trustedVerifiers: List<Verifier>
    private lateinit var mockWebServer: MockWebServer
    private lateinit var expectedValue: String
    private lateinit var vpResponseMetadata: VPResponseMetadata
    private lateinit var actualException: Exception
    private lateinit var expectedExceptionMessage: String

    @Before
    fun setUp() {
        mockkObject(NetworkManagerClient.Companion)
        openID4VP = OpenID4VP("test-OpenID4VP")
        presentationDefinition =
            """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"id_123","format":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        clientMetadata = "{\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"
        trustedVerifiers = listOf(
            Verifier(
                "https://injiverify.dev2.mosip.net", listOf(
                    "https://injiverify.qa-inji.mosip.net/redirect",
                    "https://injiverify.dev2.mosip.net/redirect"
                )
            ), Verifier(
                "https://injiverify.dev1.mosip.net", listOf(
                    "https://injiverify.qa-inji.mosip.net/redirect",
                    "https://injiverify.dev1.mosip.net/redirect"
                )
            )
        )
        mockWebServer = MockWebServer()
        mockWebServer.start(8080)
        openID4VP.authorizationRequest = AuthorizationRequest(
            clientId = "https://injiverify.dev2.mosip.net",
            responseType = "vp_token",
            responseMode = "direct_post",
            presentationDefinition = deserializeAndValidate(
                presentationDefinition,
                PresentationDefinitionSerializer
            ),
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = "fsnC8ixCs6mWyV+00k23Qg==",
            responseUri = "http://localhost:8080/injiverify.dev2.mosip.net/redirect",
            clientMetadata = deserializeAndValidate(clientMetadata, ClientMetadataSerializer),
            clientIdScheme = "did",
            redirectUri = "ji"
        )
        openID4VP.constructVerifiablePresentationToken(selectedCredentialsList)
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
    }

    @After
    fun tearDown() {
        clearAllMocks()
        mockWebServer.shutdown()
    }

    @Test
    fun `should construct VPToken in JsonString format using received selected verifiable credentials`() {
        expectedValue =
            """{"verifiableCredential":["{\"format\":\"ldp_vc\",\"verifiableCredential\":{\"credential\":{\"issuanceDate\":\"2024-08-02T16:04:35.304Z\",\"credentialSubject\":{\"face\":\"data:image/jpeg;base64,/9j/goKCyuig\",\"dateOfBirth\":\"2000/01/01\",\"id\":\"did:jwk:eyJr80435=\",\"UIN\":\"9012378996\",\"email\":\"mockuser@gmail.com\"},\"id\":\"https://domain.net/credentials/12345-87435\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-04-14T16:04:35Z\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"https://domain.net/.well-known/public-key.json\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\"},\"type\":[\"VerifiableCredential\"],\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://domain.net/.well-known/context.json\",{\"sec\":\"https://w3id.org/security#\"}],\"issuer\":\"https://domain.net/.well-known/issuer.json\"}}}","{\"verifiableCredential\":{\"credential\":{\"issuanceDate\":\"2024-08-12T18:03:35.304Z\",\"credentialSubject\":{\"face\":\"data:image/jpeg;base64,/9j/goKCyuig\",\"dateOfBirth\":\"2000/01/01\",\"id\":\"did:jwk:eyJr80435=\",\"UIN\":\"9012378996\",\"email\":\"mockuser@gmail.com\"},\"id\":\"https://domain.net/credentials/12345-87435\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-04-14T16:04:35Z\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"https://domain.net/.well-known/public-key.json\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\"},\"type\":[\"VerifiableCredential\"],\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://domain.net/.well-known/context.json\",{\"sec\":\"https://w3id.org/security#\"}],\"issuer\":\"https://domain.net/.well-known/issuer.json\"}}}","{\"format\":\"ldp_vc\",\"verifiableCredential\":{\"credential\":{\"issuanceDate\":\"2024-08-18T13:02:35.304Z\",\"credentialSubject\":{\"face\":\"data:image/jpeg;base64,/9j/goKCyuig\",\"dateOfBirth\":\"2000/01/01\",\"id\":\"did:jwk:eyJr80435=\",\"UIN\":\"9012378996\",\"email\":\"mockuser@gmail.com\"},\"id\":\"https://domain.net/credentials/12345-87435\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-04-14T16:04:35Z\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"https://domain.net/.well-known/public-key.json\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\"},\"type\":[\"VerifiableCredential\"],\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://domain.net/.well-known/context.json\",{\"sec\":\"https://w3id.org/security#\"}],\"issuer\":\"https://domain.net/.well-known/issuer.json\"}}}"],"id":"649d581c-f291-4969-9cd5-2c27385a348f","holder":""}"""
        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        val actualValue = openID4VP.constructVerifiablePresentationToken(selectedCredentialsList)

        assertEquals(expectedValue, actualValue)
    }

    @Test
    fun `should throw invalid input exception if any input param of VPResponseMetadata class is empty`() {
        vpResponseMetadata = VPResponseMetadata(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ", "RsaSignature2018", publicKey, ""
        )
        expectedExceptionMessage = "Invalid Input: vp response metadata->domain value cannot be an empty string, null, or an integer"
        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                openID4VP.shareVerifiablePresentation(vpResponseMetadata)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if Authorization Response request call returns the response with http status other than 200`() {
        val mockResponse: MockResponse = MockResponse().setResponseCode(500)
        mockWebServer.enqueue(mockResponse)
        vpResponseMetadata = VPResponseMetadata(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",
            "RsaSignature2018",
            publicKey,
            "https://123"
        )
        expectedExceptionMessage =
            "Network request failed with error response - Response{protocol=http/1.1, code=500, message=Server Error, url=http://localhost:8080/injiverify.dev2.mosip.net/redirect}"

        actualException =
            assertThrows(NetworkManagerClientExceptions.NetworkRequestFailed::class.java) {
                openID4VP.shareVerifiablePresentation(vpResponseMetadata)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if Authorization Response request call takes more time to return response than specified time`() {
        vpResponseMetadata = VPResponseMetadata(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",
            "RsaSignature2018",
            publicKey,
            "https://123"
        )
        expectedExceptionMessage = "VP sharing failed due to connection timeout"

        actualException =
            assertThrows(NetworkManagerClientExceptions.NetworkRequestTimeout::class.java) {
                openID4VP.shareVerifiablePresentation(vpResponseMetadata)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should get response if Verifiable Presentation is shared successfully to the Verifier`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "http://localhost:8080/injiverify.dev2.mosip.net/redirect",
                any(),
                any(),
                any()
            )
        } returns  mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to "Verifiable Presentation is shared successfully"
        )
        vpResponseMetadata = VPResponseMetadata(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",
            "RsaSignature2018",
            publicKey,
            "https://123",
        )
        val expectedValue = "Verifiable Presentation is shared successfully"

        val actualResponse = openID4VP.shareVerifiablePresentation(vpResponseMetadata)

        assertEquals(expectedValue, actualResponse)
    }
}