package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.createHashedDataItem
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.common.tagEncodedCbor
import io.mosip.openID4VP.common.toHex
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val classname = UnsignedMdocVPToken::class.simpleName!!

internal class UnsignedMdocVPTokenBuilder(
    private val clientId: String,
    private val responseUri: String,
    private val verifierNonce: String,
    private val mdocGeneratedNonce: String
) : UnsignedVPTokenBuilder {
    override fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<VPTokenSigningPayload?, UnsignedMdocVPToken> {
        val docTypeToDeviceAuthenticationBytes = mutableMapOf<String, String>()

        val clientIdHash = createHashedDataItem(clientId, mdocGeneratedNonce)
        val responseUriHash = createHashedDataItem(responseUri, mdocGeneratedNonce)

        val openId4VPHandover: DataItem =
            cborArrayOf(clientIdHash, responseUriHash, verifierNonce)

        val sessionTranscript: DataItem = cborArrayOf(null, null, openId4VPHandover)

        val deviceNamespaces: DataItem = cborMapOf()
        val deviceNameSpacesBytes = tagEncodedCbor(deviceNamespaces)

        credentialInputDescriptorMappings.map { credentialInputDescriptorMapping ->
            val mdocCredential = credentialInputDescriptorMapping.credential as? String
                ?: throw OpenID4VPExceptions.InvalidData(
                    "MDOC credential is not a String",
                    classname
                )
            val decodedMdocCredential = getDecodedMdocCredential(mdocCredential)
            val docType = decodedMdocCredential.get(UnicodeString("docType")).toString()

            val deviceAuthentication: DataItem = cborArrayOf(
                "DeviceAuthentication",
                sessionTranscript,
                docType,
                deviceNameSpacesBytes
            )
            val deviceAuthenticationBytes = tagEncodedCbor(deviceAuthentication)
            if (docTypeToDeviceAuthenticationBytes.containsKey(docType)) {
                throw OpenID4VPExceptions.InvalidData(
                    "Duplicate Mdoc Credentials with same doctype found",
                    classname
                )
            }
            docTypeToDeviceAuthenticationBytes[docType] =
                encodeCbor(deviceAuthenticationBytes).toHex()
            credentialInputDescriptorMapping.identifier = docType

        }
        val unsignedMdocVPToken =
            UnsignedMdocVPToken(docTypeToDeviceAuthenticationBytes = docTypeToDeviceAuthenticationBytes)


        return Pair(null, unsignedMdocVPToken)
    }
}