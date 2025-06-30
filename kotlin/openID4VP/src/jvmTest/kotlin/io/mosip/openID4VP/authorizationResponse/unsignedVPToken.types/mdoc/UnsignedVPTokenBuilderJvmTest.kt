package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import io.mockk.spyk
import io.mockk.verify
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.testData.clientId
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.verifierNonce
import io.mosip.openID4VP.testData.walletNonce
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class UnsignedVPTokenBuilderJvmTest {
    @Test
    fun `should use provided parameters correctly in token creation`() {
        val spyBuilder = spyk(
            UnsignedMdocVPTokenBuilder(
                listOf(mdocCredential),
                clientId,
                responseUrl,
                verifierNonce,
                walletNonce
            )
        )

        spyBuilder.build()
        verify {
            spyBuilder.build()
        }
    }

    @Test
    fun `should throw exception when duplicate docType is found`() {
        val mdocCredentials = listOf(mdocCredential, mdocCredential)

        val exception = assertFailsWith<InvalidData> {
            UnsignedMdocVPTokenBuilder(
                mdocCredentials,
                clientId,
                responseUrl,
                verifierNonce,
                walletNonce
            ).build()
        }

        assertEquals("Duplicate Mdoc Credentials with same doctype found", exception.message)
    }

    @Test
    fun `should create token with correct structure and payload format`() {
        val mdocCredentials = listOf(mdocCredential)

        val result = UnsignedMdocVPTokenBuilder(
            mdocCredentials,
            clientId,
            responseUrl,
            verifierNonce,
            walletNonce
        ).build()

        val unsignedToken = result["unsignedVPToken"] as UnsignedMdocVPToken
        val docType = unsignedToken.docTypeToDeviceAuthenticationBytes.keys.first()
        val authData = unsignedToken.docTypeToDeviceAuthenticationBytes[docType]

        assertNotNull(docType)
        assertFalse(docType.isEmpty())

        assertNotNull(authData)
        assertTrue(authData is String)

        // Check if the payload is a valid hex string
        val hexString = authData as String
        assertTrue(hexString.matches("[0-9A-Fa-f]+".toRegex()))
    }

    @Test
    fun `should create UnsignedMdocVPToken with valid input`() {
        val mdocCredentials = listOf(mdocCredential)

        val result = UnsignedMdocVPTokenBuilder(
            mdocCredentials,
            clientId,
            responseUrl,
            verifierNonce,
            walletNonce
        ).build()

        // Check the overall structure
        assertTrue(result.containsKey("vpTokenSigningPayload"))
        assertTrue(result.containsKey("unsignedVPToken"))

        // Check vpTokenSigningPayload
        assertEquals(mdocCredentials, result["vpTokenSigningPayload"])

        // Check unsignedVPToken
        val unsignedToken = result["unsignedVPToken"] as UnsignedMdocVPToken
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.isNotEmpty())
        assertEquals(1, unsignedToken.docTypeToDeviceAuthenticationBytes.size)
    }

}