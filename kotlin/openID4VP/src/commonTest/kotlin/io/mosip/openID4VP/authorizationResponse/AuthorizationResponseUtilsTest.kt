package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.constants.FormatType
import org.junit.Ignore
import org.junit.Test
import org.junit.jupiter.api.Assertions.*

class AuthorizationResponseUtilsTest{

    @Test
    fun `should convert the unsignedVPTokens to JSON successfully`() {
        val unsignedLdpVPToken = UnsignedLdpVPToken(
            dataToSign = "dataToSign"
        )
        val unsignedVPTokens = mapOf(FormatType.LDP_VC to unsignedLdpVPToken)
        assertEquals(
            "{\"ldp_vc\":{\"dataToSign\":\"dataToSign\"}}",
            unsignedVPTokens.toJsonString()
        )
    }
}