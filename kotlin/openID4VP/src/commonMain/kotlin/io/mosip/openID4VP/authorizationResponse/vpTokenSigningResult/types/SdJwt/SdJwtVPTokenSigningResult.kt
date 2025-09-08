package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult

data class SdJwtVPTokenSigningResult(
    val kbJwtSignatures: Map<String, String>
) : VPTokenSigningResult
