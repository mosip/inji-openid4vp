package io.mosip.openID4VP

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestFailed
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestTimeout
import io.mosip.openID4VP.testData.authorizationRequest
import io.mosip.openID4VP.testData.publicKey
import io.mosip.openID4VP.testData.setField
import io.mosip.openID4VP.testData.unsignedVPTokens
import io.mosip.openID4VP.testData.ldpvpTokenSigningResults
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.unsignedLdpVPToken
import io.mosip.openID4VP.testData.unsignedMdocVPToken
import okhttp3.Headers
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class OpenID4VPTest {

    private lateinit var openID4VP: OpenID4VP

    private val selectedLdpCredentialsList = mapOf(
        "456" to mapOf(
            FormatType.LDP_VC to listOf(
                ldpCredential1,
                ldpCredential2
            )
        ), "789" to mapOf(
            FormatType.LDP_VC to listOf(
                ldpCredential2
            )
        )
    )

    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(
            FormatType.MSO_MDOC to listOf(mdocCredential)
        )
    )

    private lateinit var mockWebServer: MockWebServer
    private lateinit var actualException: Exception
    private lateinit var expectedExceptionMessage: String

    @Before
    fun setUp() {
        mockkObject(NetworkManagerClient)
        openID4VP = OpenID4VP("test-OpenID4VP")
        mockWebServer = MockWebServer()
        mockWebServer.start(8080)
        openID4VP.authorizationRequest = authorizationRequest
        setField(
            openID4VP,
            "responseUri",
            "https://mock-verifier.com/response-uri"
        )

        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }

        openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList )
    }

    @After
    fun tearDown() {
        clearAllMocks()
        mockWebServer.shutdown()
    }

    @Test
    fun `should construct VPToken using received selected verifiable credentials`() {
        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build() } returns unsignedLdpVPToken

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build() } returns unsignedMdocVPToken

        val actualUnsignedVPTokens = openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList + selectedMdocCredentialsList)

        val expectedUnsignedVPTokens = unsignedVPTokens
        assertEquals(expectedUnsignedVPTokens[FormatType.LDP_VC], actualUnsignedVPTokens[FormatType.LDP_VC])
        assertEquals(expectedUnsignedVPTokens[FormatType.MSO_MDOC], actualUnsignedVPTokens[FormatType.MSO_MDOC])
    }

    @Test
    fun `should throw invalid input exception if any input param of VPTokenSigningResult class is empty`() {
        val ldpVPTokenSigningResult = LdpVPTokenSigningResult(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ", "RsaSignature2018", publicKey, ""
        )
        val vpTokenSigningResults = mapOf(FormatType.LDP_VC to ldpVPTokenSigningResult)
        expectedExceptionMessage =
            "Invalid Input: ldp_vp_token_signing_result->domain value cannot be an empty string, null, or an integer"
        actualException =
            assertThrows(OpenID4VPExceptions.InvalidInput::class.java) {
                openID4VP.shareVerifiablePresentation(vpTokenSigningResults)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if Authorization Response request call returns the response with http status other than 200`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                any(),
                any(),
                any()
            )
        } throws NetworkRequestFailed("Unknown error encountered")
        expectedExceptionMessage =
            "Network request failed with error response - Unknown error encountered"

        actualException =
            assertThrows(NetworkRequestFailed::class.java) {
                openID4VP.shareVerifiablePresentation(ldpvpTokenSigningResults)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if Authorization Response request call takes more time to return response than specified time`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                any(),
                any(),
                any()
            )
        } throws NetworkRequestTimeout()
        expectedExceptionMessage = "VP sharing failed due to connection timeout"

        actualException =
            assertThrows(NetworkRequestTimeout::class.java) {
                openID4VP.shareVerifiablePresentation(ldpvpTokenSigningResults)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should get response if Verifiable Presentation is shared successfully to the Verifier`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                any(),
                any(),
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to "Verifiable Presentation is shared successfully"
        )
        val expectedValue = "Verifiable Presentation is shared successfully"

        val actualResponse = openID4VP.shareVerifiablePresentation(ldpvpTokenSigningResults)

        assertEquals(expectedValue, actualResponse)
    }

    @Test
    fun `should send the error to verifier when sendErrorToVerifier is called`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                any()
            )
        } returns mapOf("body" to "VP share success")

        openID4VP.sendErrorToVerifier(OpenID4VPExceptions.InvalidData("Unsupported response_mode","OpenID4VP.kt"))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                match {
                    it["error"] == "invalid_request" &&
                            it["error_description"] == "Unsupported response_mode"
                },
                null
            )
        }
    }
}