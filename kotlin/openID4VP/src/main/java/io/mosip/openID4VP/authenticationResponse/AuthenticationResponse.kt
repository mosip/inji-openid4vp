package io.mosip.openID4VP.authenticationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.Verifier

private val className = AuthenticationResponse::class.simpleName!!
class AuthenticationResponse {
    companion object {
        fun validateAuthorizationRequestPartially(
            authorizationRequest: AuthorizationRequest,
            trustedVerifiers: List<Verifier>,
            updateAuthorizationRequest: (PresentationDefinition, ClientMetadata?) -> Unit,
            shouldValidateClient: Boolean
        ) {
            if (shouldValidateClient) {
                validateVerifier(
                    authorizationRequest.clientId,
                    authorizationRequest.responseUri,
                    trustedVerifiers
                ) ?: throw Logger.handleException(
                    exceptionType = "InvalidVerifierClientID",
                    className = className
                )
            }

            try {
                var clientMetadata: ClientMetadata? = null
                authorizationRequest.clientMetadata?.let {
                    clientMetadata =
                        deserializeAndValidate(
                            (authorizationRequest.clientMetadata).toString(),
                            ClientMetadataSerializer
                        )
                }
                val presentationDefinition: PresentationDefinition =
                    deserializeAndValidate(
                        (authorizationRequest.presentationDefinition).toString(),
                        PresentationDefinitionSerializer
                    )
                updateAuthorizationRequest(presentationDefinition, clientMetadata)
            } catch (e: Exception) {
                throw e
            }
        }

        private fun validateVerifier(
            receivedClientId: String,
            receivedResponseUri: String,
            trustedVerifiers: List<Verifier>
        ): Verifier? {
            return trustedVerifiers.find { it.clientId == receivedClientId && receivedResponseUri in it.responseUris }
        }
    }
}