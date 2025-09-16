package io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt

import io.mosip.openID4VP.authorizationResponse.mapping.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt.SdJwtVPTokenSigningResult
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.createDescriptorMapPath
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = SdJwtVPTokenBuilder::class.java.simpleName

/**
 * Builds a final SD-JWT VP Token in the format:
 *   <issuer-signed-sd-jwt>~<disclosure1>~<disclosure2>[~<signed_kb_jwt>]
 */
internal class SdJwtVPTokenBuilder : VPTokenBuilder {
    override fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Any?, io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken>,
        vpTokenSigningResult: io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult,
        rootIndex: Int
    ): Triple<List<SdJwtVPToken>, List<DescriptorMap>, Int> {
        var vpIndex = rootIndex
        val sdJwtVPTokenSigningResult = vpTokenSigningResult as SdJwtVPTokenSigningResult
        val unsignedSdJwtVPToken = unsignedVPTokenResult.second as UnsignedSdJwtVPToken
        val vpTokens = mutableListOf<SdJwtVPToken>()
        val descriptorMaps = mutableListOf<DescriptorMap>()
        credentialInputDescriptorMappings.forEach { mapping ->
            val uuid = mapping.identifier ?: throw OpenID4VPExceptions.InvalidData(
                "identifier is null in CredentialInputDescriptorMapping for SD-JWT",
                className
            )
            val sdJwtCredential = mapping.credential as? String ?: throw OpenID4VPExceptions.InvalidData(
                "SD-JWT credential is not a String",
                className
            )
            val unsignedKBJwt = unsignedSdJwtVPToken.uuidToUnsignedKBT[uuid]
            val signature = sdJwtVPTokenSigningResult.uuidToKbJWTSignature[uuid]
            val finalVPToken = when {
                unsignedKBJwt == null && signature == null -> {
                    sdJwtCredential
                }
                unsignedKBJwt != null && signature != null -> {
                    "$sdJwtCredential$unsignedKBJwt.$signature"
                }
                unsignedKBJwt != null && signature == null -> {
                    throw OpenID4VPExceptions.MissingInput(
                        "",
                        "Missing Key Binding JWT signature for uuid: $uuid",
                        className
                    )
                }
                else -> {
                    throw OpenID4VPExceptions.InvalidData(
                        "Signature present but unsigned KB-JWT missing for uuid: $uuid",
                        className,
                    )
                }
            }
            vpTokens.add(SdJwtVPToken(finalVPToken))
            descriptorMaps.add(
                DescriptorMap(
                    id = mapping.inputDescriptorId,
                    format = mapping.format.value,
                    path = createDescriptorMapPath(vpIndex),
                    pathNested = createNestedPath(mapping.inputDescriptorId, mapping.nestedPath, mapping.format)
                )
            )
            vpIndex++;
        }
        return Triple(vpTokens, descriptorMaps, vpIndex )
    }
}
