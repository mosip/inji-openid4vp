package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.exception.AuthorizationResponseExceptions
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHttpPostRequest
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val logTag = Logger.getLogTag(AuthorizationResponse::class.simpleName!!)

class AuthorizationResponse {
    companion object {
        private lateinit var vpTokenForSigning: VPTokenForSigning
        private lateinit var verifiableCredentials: Map<String, List<String>>

        fun constructVPTokenForSigning(verifiableCredentials: Map<String, List<String>>): String {
            try {
                this.verifiableCredentials = verifiableCredentials
                val verifiableCredential = mutableListOf<String>()
                verifiableCredentials.forEach { (_, vcs) ->
                    vcs.forEach { vcJson ->
                        verifiableCredential.add(vcJson)
                    }
                }
                this.vpTokenForSigning = VPTokenForSigning(
                    verifiableCredential = verifiableCredential,
                    id = UUIDGenerator.generateUUID(),
                    holder = ""
                )
                return Json.encodeToString(vpTokenForSigning)
            } catch (exception: SerializationException) {
                Logger.error(logTag, exception)
                throw AuthorizationResponseExceptions.JsonEncodingException("vpTokenForSigning")
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        fun shareVP(
            vpResponseMetadata: VPResponseMetadata,
            nonce: String,
            state: String,
            responseUri: String,
            presentationDefinitionId: String
        ): String {
            try {
                vpResponseMetadata.validate()
                var pathIndex = 0
                val proof = Proof.constructProof(
                    vpResponseMetadata, challenge = nonce
                )
                val descriptorMap = mutableListOf<DescriptorMap>()
                verifiableCredentials.forEach { (inputDescriptorId, vcs) ->
                    vcs.forEach { _ ->
                        descriptorMap.add(
                            DescriptorMap(
                                inputDescriptorId,
                                "ldp_vp",
                                "$.verifiableCredential[${pathIndex++}]"
                            )
                        )
                    }
                }
                val presentationSubmission = PresentationSubmission(
                    UUIDGenerator.generateUUID(), presentationDefinitionId, descriptorMap
                )
                val vpToken = VPToken.constructVpToken(this.vpTokenForSigning, proof)

                return constructHttpRequestBody(
                    vpToken,
                    presentationSubmission,
                    responseUri, state
                )
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        private fun constructHttpRequestBody(
            vpToken: VPToken,
            presentationSubmission: PresentationSubmission,
            responseUri: String, state: String
        ): String {
            val encodedVPToken: String
            val encodedPresentationSubmission: String
            try {
                encodedVPToken = Json.encodeToString(vpToken)
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw AuthorizationResponseExceptions.JsonEncodingException("vpToken")
            }
            try {
                encodedPresentationSubmission = Json.encodeToString(presentationSubmission)
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw AuthorizationResponseExceptions.JsonEncodingException("presentationSubmission")
            }

            try {
                val bodyParams = mapOf(
                    "vp_token" to encodedVPToken,
                    "presentation_submission" to encodedPresentationSubmission,
                    "state" to state
                )

                return sendHttpPostRequest(responseUri, bodyParams)
            } catch (exception: Exception) {
                throw exception
            }
        }
    }
}