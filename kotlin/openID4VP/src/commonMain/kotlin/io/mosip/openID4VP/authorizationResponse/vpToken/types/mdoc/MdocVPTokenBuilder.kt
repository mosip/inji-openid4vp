package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc


import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.common.mapSigningAlgorithmToProtectedAlg
import io.mosip.openID4VP.common.tagEncodedCbor
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.common.createDescriptorMapPath
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = MdocVPTokenBuilder::class.java.simpleName

internal class MdocVPTokenBuilder : VPTokenBuilder {
    override fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Any?, UnsignedVPToken>,
        vpTokenSigningResult: VPTokenSigningResult,
        rootIndex: Int
    ): Triple<List<MdocVPToken>, List<DescriptorMap>, Int> {
        val mdocVPTokenSigningResult = vpTokenSigningResult as MdocVPTokenSigningResult
        mdocVPTokenSigningResult.validate()

        val documents = mutableListOf<DataItem>()
        val descriptorMaps = mutableListOf<DescriptorMap>()
        credentialInputDescriptorMappings.forEach {credentialInputDescriptorMapping ->
            val mdocCredential = credentialInputDescriptorMapping.credential as String

            val document = getDecodedMdocCredential(mdocCredential)
            val credentialDocType = document.get(UnicodeString("docType")).toString()

            val deviceAuthentication = mdocVPTokenSigningResult.docTypeToDeviceAuthentication[credentialDocType]
                ?: throwMissingInput("Device authentication signature not found for mdoc credential docType $credentialDocType")

            val signature = deviceAuthentication.signature
            val mdocAuthenticationAlgorithm = deviceAuthentication.algorithm

            val deviceSignature = createDeviceSignature(mdocAuthenticationAlgorithm, signature)

            val deviceNamespacesBytes = tagEncodedCbor(cborMapOf())
            val deviceAuth = cborMapOf("deviceSignature" to deviceSignature)
            val deviceSigned = cborMapOf(
                "deviceAuth" to deviceAuth,
                "nameSpaces" to deviceNamespacesBytes
            )

            document.put(UnicodeString("deviceSigned"), deviceSigned)

            documents.add(document)
            descriptorMaps.add(
                DescriptorMap(
                    id = credentialInputDescriptorMapping.inputDescriptorId,
                    format = credentialInputDescriptorMapping.format.value,
                    path = createDescriptorMapPath(rootIndex),
                    pathNested = createNestedPath(credentialInputDescriptorMapping.inputDescriptorId, credentialInputDescriptorMapping.nestedPath, credentialInputDescriptorMapping.format)
                )
            )
        }

        val response = cborMapOf(
            "version" to "1.0",
            "documents" to cborArrayOf(*documents.toTypedArray()),
            "status" to 0
        )
        val mdocVPToken = MdocVPToken(encodeToBase64Url(encodeCbor(response)))

        return Triple(listOf(mdocVPToken), descriptorMaps, rootIndex + 1)
    }

    private fun createDeviceSignature(
        signingAlgorithm: String,
        signature: String
    ): DataItem {
        val base64DecodedSignature = decodeFromBase64Url(signature)
        val cborEncodedSignature = encodeCbor(ByteString(base64DecodedSignature))

        val protectedSigningAlgorithm = mapSigningAlgorithmToProtectedAlg(signingAlgorithm)

        val protectedHeader = encodeCbor(cborMapOf(1 to protectedSigningAlgorithm))
        val unprotectedHeader = cborMapOf()

        return cborArrayOf(protectedHeader, unprotectedHeader, null, cborEncodedSignature)
    }

    private fun throwMissingInput(message: String): Nothing {
        throw OpenID4VPExceptions.MissingInput("",message, className)
    }
}
