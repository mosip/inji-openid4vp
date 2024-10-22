package io.mosip.openID4VP

import io.mosip.openID4VP.authenticationResponse.AuthenticationResponse
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHttpPostRequest

private val logTag = Logger.getLogTag(AuthorizationResponse::class.simpleName!!)
class OpenID4VP(private val traceabilityId: String) {
    lateinit var authorizationRequest: AuthorizationRequest
    private var responseUri: String? = null

    private fun setResponseUri(responseUri: String) {
        this.responseUri = responseUri
    }

    private fun updateAuthorizationRequest(
        presentationDefinition: PresentationDefinition,
        clientMetadata: ClientMetadata?
    ) {
        this.authorizationRequest.presentationDefinition = presentationDefinition
        this.authorizationRequest.clientMetadata = clientMetadata
    }

    fun authenticateVerifier(
        encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>
    ): AuthorizationRequest {
        try {
            Logger.setTraceability(traceabilityId)
            authorizationRequest = AuthorizationRequest.validateAndGetAuthorizationRequest(
                encodedAuthorizationRequest, ::setResponseUri
            )
            AuthenticationResponse.validateAuthorizationRequestPartially(
                authorizationRequest,
                trustedVerifiers,
                ::updateAuthorizationRequest,
            )
            return this.authorizationRequest
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, List<String>>): String {
        try {
            return AuthorizationResponse.constructVPTokenForSigning(
                verifiableCredentials
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata): String {
        try {
            return AuthorizationResponse.shareVP(
                vpResponseMetadata,
                authorizationRequest.nonce,
                authorizationRequest.responseUri,
                (this.authorizationRequest.presentationDefinition as PresentationDefinition).id
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun sendErrorToVerifier(exception: Exception) {
        responseUri?.let {
            try {
                sendHttpPostRequest(
                    it, mapOf("error" to exception.message!!)
                )
            } catch (exception: Exception) {
                Logger.error(
                    logTag,
                    Exception("Unexpected error occurred while sending the error to verifier.")
                )
            }
        }
    }
}