package io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt

import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt.SdJwtVPTokenSigningResult
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = SdJwtVPTokenBuilder::class.java.simpleName

/**
 * Builds a final SD-JWT VP Token in the format:
 *   <issuer-signed-sd-jwt>~<disclosure1>~<disclosure2>~<signed_kb_jwt>
 */
class SdJwtVPTokenBuilder(
    private val sdJwtVPTokenSigningResult: SdJwtVPTokenSigningResult,
    private val sdJwtCredentials: MutableMap<String,String>,
    private val unsignedKBJwts: MutableMap<String,String>,
    private val uuid: String
) : VPTokenBuilder {

    override fun build(): SdJwtVPToken {
        val sdJwtCredential = sdJwtCredentials[uuid]
            ?: throw OpenID4VPExceptions.MissingInput(
                uuid,
                "Missing SD-JWT credential for uuid: $uuid",
                className
            )

        val unsignedKBJwt = unsignedKBJwts[uuid]
            ?: throw OpenID4VPExceptions.MissingInput(
                uuid,
                "Missing unsigned Key Binding JWT for uuid: $uuid",
                className
            )

        val signature = sdJwtVPTokenSigningResult.kbJwtSignatures[uuid]
            ?: throw OpenID4VPExceptions.MissingInput(
                uuid,
                "Missing Key Binding JWT signature for uuid: $uuid",
                className
            )

        val finalToken = "$sdJwtCredential~$unsignedKBJwt.$signature"
        return SdJwtVPToken(finalToken)
    }
}
