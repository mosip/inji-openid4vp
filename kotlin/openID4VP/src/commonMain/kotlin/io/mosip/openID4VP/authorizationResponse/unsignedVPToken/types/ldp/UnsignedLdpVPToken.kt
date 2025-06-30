package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken

data class UnsignedLdpVPToken(
    val dataToSign: String
) : UnsignedVPToken
