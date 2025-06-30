package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.*
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.testData.clientId
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.verifierNonce
import io.mosip.openID4VP.testData.walletNonce
import kotlin.test.*

class UnsignedMdocVPTokenBuilderTest {


    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }




    @Test
    fun `should create token with empty device auth when mdocCredentials list is empty`() {
        val result = UnsignedMdocVPTokenBuilder(
            emptyList(),
            clientId,
            responseUrl,
            verifierNonce,
            walletNonce
        ).build()

        val unsignedToken = result["unsignedVPToken"] as UnsignedMdocVPToken
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.isEmpty())

        // Verify payload is empty list
        assertEquals(emptyList<String>(), result["vpTokenSigningPayload"])
    }



    @Test
    fun `should handle multiple different mdoc credentials correctly`() {
        mockkStatic(::getDecodedMdocCredential)

        val secondMdocCredential = "second_mdoc_credential"

        val firstDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType1"))
        }

        val secondDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType2"))
        }

        every { getDecodedMdocCredential(mdocCredential) } returns firstDecodedMap
        every { getDecodedMdocCredential(secondMdocCredential) } returns secondDecodedMap

        val mdocCredentials = listOf(mdocCredential, secondMdocCredential)

        val result = UnsignedMdocVPTokenBuilder(
            mdocCredentials,
            clientId,
            responseUrl,
            verifierNonce,
            walletNonce
        ).build()

        val unsignedToken = result["unsignedVPToken"] as UnsignedMdocVPToken
        assertEquals(2, unsignedToken.docTypeToDeviceAuthenticationBytes.size)
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.containsKey("docType1"))
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.containsKey("docType2"))
    }

    @Test
    fun `should throw exception for malformed mdoc credential`() {
        mockkStatic(::getDecodedMdocCredential)

        every { getDecodedMdocCredential(any()) } throws IllegalArgumentException("Invalid CBOR data")

        val exception = assertFailsWith<IllegalArgumentException> {
            UnsignedMdocVPTokenBuilder(
                listOf("invalid_mdoc_credential"),
                clientId,
                responseUrl,
                verifierNonce,
                walletNonce
            ).build()
        }

        assertEquals("Invalid CBOR data", exception.message)
    }


}
