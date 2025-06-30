package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType

class VPTokenFactory(
    private val vpTokenSigningResult: VPTokenSigningResult,
    private val vpTokenSigningPayload: Any,
    private val nonce: String
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
        }
    }
}

