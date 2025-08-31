package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.constants.ContentType.APPLICATION_JWT
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import okhttp3.Headers
import java.security.PublicKey

private val className = DidSchemeAuthorizationRequestHandler::class.simpleName!!
private const val KEY_ID = "kid"

class DidSchemeAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    walletMetadata: WalletMetadata?,
    setResponseUri: (String) -> Unit,
    walletNonce: String,
) : ClientIdSchemeBasedAuthorizationRequestHandler(
    authorizationRequestParameters,
    walletMetadata,
    setResponseUri,
    walletNonce
) {
    override fun isRequestUriSupported(): Boolean {
        return true
    }

    override fun isRequestObjectSupported(): Boolean {
        return false
    }

    override fun extractPublicKey(algorithm: RequestSigningAlgorithm, kid: String?): PublicKey {
        val didUrl = getStringValue(authorizationRequestParameters, CLIENT_ID.value)
            ?: throw OpenID4VPExceptions.InvalidData(
                "client_id is not present in authorization request",
                className
            )
        return DidPublicKeyResolver().resolve(didUrl, kid)
    }

    override fun process(walletMetadata: WalletMetadata): WalletMetadata {
        if (walletMetadata.requestObjectSigningAlgValuesSupported.isNullOrEmpty())
            throw OpenID4VPExceptions.InvalidData(
                "request_object_signing_alg_values_supported is not present in wallet metadata",
                className
            )
        return walletMetadata
    }

    override fun getHeadersForAuthorizationRequestUri(): Map<String, String> {
        return mapOf(
            "content-type" to APPLICATION_FORM_URL_ENCODED.value,
            "accept" to APPLICATION_JWT.value
        )
    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains(APPLICATION_JWT.value, ignoreCase = true) == true

    private fun validateAuthorizationRequestSigningAlgorithm(headers: MutableMap<String, Any>) {
        if (shouldValidateWithWalletMetadata) {
            val alg = headers["alg"] as String
            walletMetadata?.let {
                if (!it.requestObjectSigningAlgValuesSupported!!.contains(
                        RequestSigningAlgorithm.fromValue(
                            alg
                        )
                    )
                )
                    throw OpenID4VPExceptions.InvalidData(
                        "request_object_signing_alg is not support by wallet",
                        className
                    )
            }
        }
    }
}

