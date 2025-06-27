package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.exceptions.Exceptions.InvalidData
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.responseUrl
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test


class UnsignedMdocVPTokenBuilderTest {

    private val clientId = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
    private val responseUri = responseUrl
    private val verifierNonce = "GM12ZywLxmA0PjQFevb/WQ=="
    private val walletNonce = "P0RVGUe5OoDctvuK"

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
        every { Log.d(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should create UnsignedMdocVPToken with valid input`() {
        val mdocCredentials = listOf(mdocCredential)

        val result = UnsignedMdocVPTokenBuilder(
            mdocCredentials,
            clientId,
            responseUri,
            verifierNonce,
            walletNonce
        ).build() as UnsignedMdocVPToken

        assertNotNull(result)
        assertTrue(result.docTypeToDeviceAuthenticationBytes.isNotEmpty())
        assertEquals(1, result.docTypeToDeviceAuthenticationBytes.size)
    }

    @Test
    fun `should throw exception when duplicate docType is found`() {
        val mdocCredentials = listOf(mdocCredential, mdocCredential)

        val actualException =
            assertThrows(OpenID4VPExceptions.InvalidData::class.java) {
                UnsignedMdocVPTokenBuilder(
                    mdocCredentials,
                    clientId,
                    responseUri,
                    verifierNonce,
                    walletNonce
                ).build() as UnsignedMdocVPToken
            }

       assertEquals("Duplicate Mdoc Credentials with same doctype found", actualException.message)
    }


    @Test
    fun `should create token with empty device auth when mdocCredentials list is empty`() {
        val result = UnsignedMdocVPTokenBuilder(
            emptyList(),
            clientId,
            responseUri,
            verifierNonce,
            walletNonce
        ).build() as UnsignedMdocVPToken

        assertNotNull(result)
        assertTrue(result.docTypeToDeviceAuthenticationBytes.isEmpty())
    }

    @Test
    fun `should create token with correct structure and payload format`() {
        val mdocCredentials = listOf(mdocCredential)

        val result = UnsignedMdocVPTokenBuilder(
            mdocCredentials,
            clientId,
            responseUri,
            verifierNonce,
            walletNonce
        ).build() as UnsignedMdocVPToken

        val docType = result.docTypeToDeviceAuthenticationBytes.keys.first()
        val authData = result.docTypeToDeviceAuthenticationBytes[docType]

        assertNotNull(docType)
        assertFalse(docType.isEmpty())

        assertNotNull(authData)
        assertTrue(authData is String)

        // Check if the payload is a valid hex string
        val hexString = authData as String
        assertTrue(hexString.matches("[0-9A-Fa-f]+".toRegex()))
    }

}


