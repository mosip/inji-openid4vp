package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt.SdJwtVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt.SdJwtVPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType

class VPTokenFactory(
    private val vpTokenSigningResult: VPTokenSigningResult,
    private val unsignedVPTokens: Any?,
    private val vpTokenSigningPayload: Any,
    private val nonce: String,
    private val uuid: String? = null
) {

    fun getVPTokenBuilder(credentialFormat: FormatType): VPTokenBuilder {
        return when (credentialFormat) {
            FormatType.LDP_VC -> LdpVPTokenBuilder(
                ldpVPTokenSigningResult = vpTokenSigningResult as LdpVPTokenSigningResult,
                unsignedLdpVPToken = vpTokenSigningPayload as VPTokenSigningPayload,
                nonce = nonce
            )
            FormatType.MSO_MDOC -> MdocVPTokenBuilder(
                mdocVPTokenSigningResult = vpTokenSigningResult as MdocVPTokenSigningResult,
                mdocCredentials = vpTokenSigningPayload as List<String>,
            )

            FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> SdJwtVPTokenBuilder(
                sdJwtVPTokenSigningResult = vpTokenSigningResult as SdJwtVPTokenSigningResult,
                sdJwtCredentials = vpTokenSigningPayload as MutableMap<String,String>,
                unsignedKBJwts = unsignedVPTokens as MutableMap<String,String>,
                uuid = uuid!!//TODO::throw error if null
            )
        }
    }
}

