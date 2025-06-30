package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.common.DateUtil.formattedCurrentDateTime
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.constants.SignatureAlgorithm.Ed25519Signature2020
import io.mosip.openID4VP.constants.SignatureAlgorithm.JsonWebSignature2020

typealias VPTokenSigningPayload = LdpVPToken

class UnsignedLdpVPTokenBuilder(
    private val verifiableCredential: List<Any>,
    private val id: String,
    private val holder: String,
    private val challenge: String,
    private val domain: String,
    private val signatureSuite: String
) : UnsignedVPTokenBuilder {
    override fun build(): Map<String, Any> {
        val context = mutableListOf("https://www.w3.org/2018/credentials/v1")

        if (signatureSuite == Ed25519Signature2020.value) {
            context.add("https://w3id.org/security/suites/ed25519-2020/v1")
        }
        if (signatureSuite == JsonWebSignature2020.value) {
            context.add("https://w3id.org/security/suites/jws-2020/v1")
        }

        val vpTokenSigningPayload = VPTokenSigningPayload(
            context = context,
            type = listOf("VerifiablePresentation"),
            verifiableCredential = verifiableCredential,
            id = id,
            holder = holder,
            proof = Proof(
                type = signatureSuite,
                created = formattedCurrentDateTime(),
                verificationMethod = holder,
                domain = domain,
                challenge = challenge
            )
        )

        val vpTokenSigningPayloadString = encodeToJsonString(
            vpTokenSigningPayload,
            "vpTokenSigningPayload",
            VPTokenSigningPayload::class.java.simpleName
        )

        val dataToSign =
            URDNA2015Canonicalization.canonicalize(vpTokenSigningPayloadString)
        val unsignedLdpVPToken = UnsignedLdpVPToken(dataToSign = dataToSign)
        return mapOf(
            "vpTokenSigningPayload" to vpTokenSigningPayload,
            "unsignedVPToken" to unsignedLdpVPToken
        )
    }
}