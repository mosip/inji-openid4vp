package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc

import io.mockk.*
import kotlin.test.*

class MdocVPTokenSigningResultTest {

    private lateinit var mockDeviceAuthentication1: DeviceAuthentication
    private lateinit var mockDeviceAuthentication2: DeviceAuthentication
    private lateinit var deviceAuthenticationMap: Map<String, DeviceAuthentication>

    @BeforeTest
    fun setUp() {
        mockDeviceAuthentication1 = mockk(relaxed = true)
        mockDeviceAuthentication2 = mockk(relaxed = true)
        deviceAuthenticationMap = mapOf(
            "doctype1" to mockDeviceAuthentication1,
            "doctype2" to mockDeviceAuthentication2
        )
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should call validate on each device authentication in map`() {
        val mdocVPTokenSigningResult = MdocVPTokenSigningResult(deviceAuthenticationMap)
        mdocVPTokenSigningResult.validate()
        verify { mockDeviceAuthentication1.validate() }
        verify { mockDeviceAuthentication2.validate() }
    }

    @Test
    fun `should handle empty map`() {
        val emptyMap = emptyMap<String, DeviceAuthentication>()
        val mdocVPTokenSigningResult = MdocVPTokenSigningResult(emptyMap)
        mdocVPTokenSigningResult.validate() // Should not throw
    }
}
