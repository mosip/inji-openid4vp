package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.exceptions.Exceptions.InvalidInput
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows


class DeviceAuthenticationTest {

    @Before
    fun setUp() {
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
    }

    @Test
    fun `validate succeeds with valid inputs`() {
        val deviceAuth = DeviceAuthentication("testSignature", "SHA256withRSA")
        assertDoesNotThrow { deviceAuth.validate() }
    }

    @Test
    fun `validate throws exception with null signature string`() {
        val deviceAuth = DeviceAuthentication("null", "SHA256withRSA")

        val exception = assertThrows<OpenID4VPExceptions.InvalidInput> {
            deviceAuth.validate()
        }
        assertEquals("Invalid Input: mdoc_vp_token_signing_result->device_authentication->signature value cannot be empty or null", exception.message)
    }

    @Test
    fun `validate throws exception with null algorithm string`() {
        val deviceAuth = DeviceAuthentication("testSignature", "null")

        val exception = assertThrows<OpenID4VPExceptions.InvalidInput> {
            deviceAuth.validate()
        }
        assertEquals("Invalid Input: mdoc_vp_token_signing_result->device_authentication->algorithm value cannot be empty or null", exception.message)
    }

}