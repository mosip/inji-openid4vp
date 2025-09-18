package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt.SdJwtVPTokenBuilder
import io.mosip.openID4VP.constants.FormatType


internal class VPTokenFactory {
    companion object {
        fun getVPTokenBuilder(credentialFormat: FormatType): VPTokenBuilder {
            return when (credentialFormat) {
                FormatType.LDP_VC -> LdpVPTokenBuilder()
                FormatType.MSO_MDOC -> MdocVPTokenBuilder()

                FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> {
                    SdJwtVPTokenBuilder()
                }

            }
        }
    }
}

