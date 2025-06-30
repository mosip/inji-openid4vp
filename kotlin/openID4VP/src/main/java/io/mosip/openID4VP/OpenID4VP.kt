package io.mosip.openID4VP

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
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
        walletMetadata: WalletMetadata? = null,
        shouldValidateClient: Boolean = false
    ): AuthorizationRequest {
        try {
            Logger.setTraceabilityId(traceabilityId)
            authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest, trustedVerifiers, walletMetadata, ::setResponseUri,shouldValidateClient
            )
            return this.authorizationRequest
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun constructUnsignedVPToken(verifiableCredentials: Map<String, Map<FormatType, List<Any>>>): Map<FormatType, UnsignedVPToken> {
        try {
            return authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = verifiableCredentials,
                authorizationRequest = this.authorizationRequest,
                responseUri = this.responseUri!!
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>): String {
        try {
            return this.authorizationResponseHandler.shareVP(
                authorizationRequest = this.authorizationRequest,
                vpTokenSigningResults = vpTokenSigningResults,
                responseUri = this.responseUri!!
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun sendErrorToVerifier(exception: Exception) {
        responseUri?.let { uri ->
            try {
                val errorPayload: Map<String, String> = when (exception) {
                    is OpenID4VPExceptions -> exception.toErrorResponse()
                    else -> OpenID4VPExceptions.GenericFailure(
                        message = exception.message ?: "Unknown internal error",
                        className = "OpenID4VP.kt"
                    ).toErrorResponse()
                }
                sendHTTPRequest(
                    url = uri,
                    method = HttpMethod.POST,
                    bodyParams = errorPayload
                )
            } catch (e: Exception) {
                Logger.error(
                    logTag,
                    Exception("Unexpected error occurred while sending the error to verifier: ${e.message}")
                )
            }
        }
    }
    }
