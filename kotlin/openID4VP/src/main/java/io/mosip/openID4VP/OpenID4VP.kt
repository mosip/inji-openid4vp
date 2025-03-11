package io.mosip.openID4VP

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.toJson
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val logTag = Logger.getLogTag(OpenID4VP::class.simpleName!!)

class OpenID4VP(private val traceabilityId: String) {
    lateinit var authorizationRequest: AuthorizationRequest
    private var authorizationResponseHandler: AuthorizationResponseHandler =
        AuthorizationResponseHandler()
    private var responseUri: String? = null

    private fun setResponseUri(responseUri: String) {
        this.responseUri = responseUri
    }

    @JvmOverloads
    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = false,
    ): AuthorizationRequest {
        try {
            Logger.setTraceabilityId(traceabilityId)
            authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest,
                trustedVerifiers,
                ::setResponseUri,
                shouldValidateClient
            )
            return this.authorizationRequest
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, Map<FormatType, List<String>>>): Map<String, String> {
        try {
            val vpTokensForSigning =
                authorizationResponseHandler.constructVPTokenForSigning(
                    credentialsMap = verifiableCredentials,
                    holder = ""
                )

            return vpTokensForSigning.toJson()
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpResponsesMetadata: Map<FormatType, VPResponseMetadata>): String {
        try {
            return this.authorizationResponseHandler.shareVP(
                authorizationRequest = this.authorizationRequest,
                vpResponsesMetadata = vpResponsesMetadata,
                responseUri = this.responseUri!!
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun sendErrorToVerifier(exception: Exception) {
        responseUri?.let {
            try {
                sendHTTPRequest(
                    url = it, method = HTTP_METHOD.POST, mapOf("error" to exception.message!!)
                )
            } catch (exception: Exception) {
                Logger.error(
                    logTag,
                    Exception("Unexpected error occurred while sending the error to verifier: ${exception.message}")
                )
            }
        }
    }
}