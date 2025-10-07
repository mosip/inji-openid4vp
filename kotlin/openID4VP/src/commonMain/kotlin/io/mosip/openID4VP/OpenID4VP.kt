package io.mosip.openID4VP


import io.mosip.openID4VP.authorizationRequest.*
import io.mosip.openID4VP.authorizationResponse.*
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.*
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.constants.*
import io.mosip.openID4VP.common.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

class OpenID4VP @JvmOverloads constructor(
    private val traceabilityId: String,
    private var walletMetadata: WalletMetadata? = null
) {
    private var authorizationResponseHandler = AuthorizationResponseHandler()
    private var responseUri: String? = null
    private lateinit var walletNonce: String
    var authorizationRequest: AuthorizationRequest? = null
    private val className = OpenID4VP::class.simpleName.orEmpty()


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

    /**
     * Sends Authorization error to the Verifier and returns the response from the Verifier.
     * The response body from Verifier response is returned as a String.
     */
    fun sendErrorResponseToVerifier(exception: Exception): String {
        val sendAuthorizationError = authorizationResponseHandler.sendAuthorizationError(
            this.responseUri,
            this.authorizationRequest,
            exception
        )
        return sendAuthorizationError
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

    /** Sends Authorization error to the verifier */
    @Deprecated(
        message = "This does not support listening the response from the verifier",
        replaceWith = ReplaceWith("sendErrorResponseToVerifier(exception)"),
        level = DeprecationLevel.WARNING
    )
    fun sendErrorToVerifier(exception: Exception) {
        this.safeSendError(exception)
    }

    // Ensures that any error occurring in the flow is sent to the Verifier
    // The Verifier's response is attached to the exception for further usage
    private fun safeSendError(exception: Exception) {
        try {
            val verifierResponse = sendErrorResponseToVerifier(exception)
            (exception as? OpenID4VPExceptions)?.setResponse(verifierResponse)
        } catch (error: Exception) {
            OpenID4VPExceptions.error(error.message ?: error.localizedMessage, className)
        }
    }
}
