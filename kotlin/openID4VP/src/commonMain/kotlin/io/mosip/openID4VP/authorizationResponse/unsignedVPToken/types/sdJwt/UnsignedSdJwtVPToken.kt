package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken

data class UnsignedSdJwtVPToken(
    val uuidToUnsignedKBT: Map<String,String>
) : UnsignedVPToken
