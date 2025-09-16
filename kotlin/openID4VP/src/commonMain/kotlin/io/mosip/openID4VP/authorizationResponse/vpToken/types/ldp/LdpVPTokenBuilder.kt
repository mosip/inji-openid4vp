package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.mapping.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.VPFormatType

internal class LdpVPTokenBuilder(
    val nonce: String
) : VPTokenBuilder {
    override fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Any?, io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken>,
        vpTokenSigningResult: io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult,
        rootIndex: Int
    ): Triple<List<VPToken>, List<DescriptorMap>, Int> {
        val ldpVPTokenSigningResult = vpTokenSigningResult as LdpVPTokenSigningResult
        ldpVPTokenSigningResult.validate()
        val unsignedLdpVPToken = unsignedVPTokenResult.first as VPTokenSigningPayload

        val proof = unsignedLdpVPToken.proof!!.apply {
            proofValue = (ldpVPTokenSigningResult).proofValue
            jws = ldpVPTokenSigningResult.jws
        }
        val ldpVPToken = LdpVPToken(
            unsignedLdpVPToken.context,
            unsignedLdpVPToken.type,
            unsignedLdpVPToken.verifiableCredential,
            unsignedLdpVPToken.id,
            unsignedLdpVPToken.holder,
            proof
        )
        val descriptorMaps = credentialInputDescriptorMappings.map { mapping ->
            DescriptorMap(
                id = mapping.inputDescriptorId,
                format = VPFormatType.LDP_VP.value,
                path = "$[$rootIndex]",
                pathNested = createNestedPath(mapping.inputDescriptorId, mapping.nestedPath, FormatType.LDP_VC)
            )
        }
        return Triple(listOf(ldpVPToken), descriptorMaps, rootIndex + 1)
    }
}