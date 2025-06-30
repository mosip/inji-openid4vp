package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult

class LdpVPTokenBuilder(
    val ldpVPTokenSigningResult: LdpVPTokenSigningResult,
    val unsignedLdpVPToken: VPTokenSigningPayload,
    val nonce: String
) : VPTokenBuilder {
    override fun build(): LdpVPToken {
        ldpVPTokenSigningResult.validate()
        val ldpVPToken = LdpVPToken(
            unsignedLdpVPToken.context,
            unsignedLdpVPToken.type,
            unsignedLdpVPToken.verifiableCredential,
            unsignedLdpVPToken.id,
            unsignedLdpVPToken.holder,
            unsignedLdpVPToken.proof!!.apply {
                proofValue = ldpVPTokenSigningResult.proofValue
                jws = ldpVPTokenSigningResult.jws
            }
        )
        return ldpVPToken
    }
}