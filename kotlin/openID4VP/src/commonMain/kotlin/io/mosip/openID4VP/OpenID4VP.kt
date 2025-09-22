package io.mosip.openID4VP


import io.mosip.openID4VP.authorizationRequest.*
import io.mosip.openID4VP.authorizationResponse.*
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.*
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.constants.*
import io.mosip.openID4VP.common.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.networkManager.NetworkResponse

class OpenID4VP @JvmOverloads constructor(
    private val traceabilityId: String,
    private var walletMetadata: WalletMetadata? =  null
) {
    private  var authorizationResponseHandler = AuthorizationResponseHandler()
    private var responseUri: String? = null
    private lateinit var walletNonce: String
    var authorizationRequest: AuthorizationRequest? = null
    private val className = OpenID4VP::class.simpleName.orEmpty()


    private val logTag: String
        get() = "INJI-OpenID4VP : class name - ${OpenID4VP::class.simpleName} | traceID - $traceabilityId"

    /** Begins the authentication by validating the incoming Authorization request */
    @JvmOverloads
    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = true
    ): AuthorizationRequest {
        return try {
            walletNonce = generateNonce()
            authorizationRequest = null
            responseUri = null
            authorizationResponseHandler = AuthorizationResponseHandler()
            val authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest,
                trustedVerifiers,
                walletMetadata,
                ::setResponseUri,
                shouldValidateClient,
                walletNonce
            )
            this.authorizationRequest = authorizationRequest
            authorizationRequest
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    /** Builds the unsigned VP token from VCs */
    fun constructUnsignedVPToken(
        verifiableCredentials: Map<String, Map<FormatType, List<Any>>>,
        holderId: String? = null,
        signatureSuite: String? = null
    ): Map<FormatType, UnsignedVPToken> {
        return try {
            authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = verifiableCredentials,
                authorizationRequest = authorizationRequest!!,
                responseUri = responseUri!!,
                holderId = holderId,
                signatureSuite = signatureSuite,
                nonce = walletNonce
            )
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    /** Sends the final signed VP token response to the verifier */
    fun shareVerifiablePresentation(
        vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>
    ): String {
        return try {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest!!,
                vpTokenSigningResults = vpTokenSigningResults,
                responseUri = responseUri!!
            )
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    /** Sends Authorization error to the verifier */
    fun sendErrorToVerifier(exception: Exception): NetworkResponse {
        if (responseUri == null) {
            throw OpenID4VPExceptions.ErrorDispatchFailure(
                message = "Response URI is not set. Cannot send error to verifier.",
                className = className
            )
        } else {
            try {
                val errorPayload = when (exception) {
                    is OpenID4VPExceptions -> exception.toErrorResponse()
                    else -> OpenID4VPExceptions.GenericFailure(
                        message = exception.message ?: "Unknown internal error",
                        className = OpenID4VP::class.simpleName.orEmpty()
                    ).toErrorResponse()
                }.apply {
                    authorizationRequest!!.state?.takeIf { it.isNotBlank() }?.let {
                        this[OpenID4VPErrorFields.STATE] = it
                    }
                }

                val errorDispatchResult = sendHTTPRequest(
                    url = responseUri!!,
                    method = HttpMethod.POST,
                    bodyParams = errorPayload,
                    headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
                )
//                TODO: Add unit tests to verify this
                (exception as? OpenID4VPExceptions)?.networkResponse = errorDispatchResult

                return errorDispatchResult
            } catch (err: Exception) {
                throw OpenID4VPExceptions.ErrorDispatchFailure(
                    message = "Failed to send error to verifier: ${err.message}",
                    className = className
                )
            }
        }
    }

    @Deprecated("supports accepting wallet metadata")
    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = true,
        walletMetadata: WalletMetadata?
    ): AuthorizationRequest {
        return try {
            walletNonce = generateNonce()
            val authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest,
                trustedVerifiers,
                walletMetadata,
                ::setResponseUri,
                shouldValidateClient,
                walletNonce
            )
            this.authorizationRequest = authorizationRequest
            authorizationRequest
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    @Deprecated("Supports constructing VP token for LDP VC without canonicalization of the data sent for signing")
    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, List<String>>): String {
        return try {
            authorizationResponseHandler.constructUnsignedVPTokenV1(
                verifiableCredentials,
                authorizationRequest!!,
                responseUri!!
            )
        } catch (exception: Exception) {
            this.safeSendError(exception)
            throw exception
        }
    }

    @Deprecated("Supports only direct POST response mode for LDP VC. Use shareVerifiablePresentation with VPTokenSigningResults instead")
    fun shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata): String {
        return try {
            authorizationResponseHandler.shareVPV1(
                vpResponseMetadata,
                authorizationRequest!!,
                responseUri!!
            )
        } catch (exception: Exception) {
            this.safeSendError(exception)
            throw exception
        }
    }

    private fun setResponseUri(uri: String) {
        this.responseUri = uri
    }

    private fun safeSendError(exception: Exception) {
        try {
            sendErrorToVerifier(exception)
        } catch (error: Exception) {
            OpenID4VPExceptions.error(error.message ?: error.localizedMessage, className)
        }
    }

    private fun safeSendError(exception: OpenID4VPExceptions) {
        try {
            sendErrorToVerifier(exception)
        } catch (error: Exception) {
            OpenID4VPExceptions.error(error.message ?: error.localizedMessage, className)
        }
    }
}
