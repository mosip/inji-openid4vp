package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt.SdJwtVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions


internal class VPTokenFactory(
    private val vpTokenSigningResult: VPTokenSigningResult,
    private val unsignedVPTokens: Any?,
    private val vpTokenSigningPayload: Any,
    private val nonce: String,
    private val uuid: String? = null
) {

    private val className = VPTokenFactory::class.simpleName!!
    fun getVPTokenBuilder(credentialFormat: FormatType): VPTokenBuilder {
        return when (credentialFormat) {
            FormatType.LDP_VC -> LdpVPTokenBuilder(
                nonce = nonce
            )
            FormatType.MSO_MDOC -> MdocVPTokenBuilder()

            FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> {
                uuid ?: throw OpenID4VPExceptions.MissingInput(
                    "",
                    "UUID is required for SD-JWT VP Token but was null.",
                    className
                )

                SdJwtVPTokenBuilder()
            }

        }
    }
}

