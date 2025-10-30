package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import java.security.PublicKey

private val className = DidSchemeAuthorizationRequestHandler::class.simpleName!!

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
    override fun isSignedRequestSupported(): Boolean {
        return true
    }

    override fun isUnsignedRequestSupported(): Boolean {
        return false
    }

    override fun clientIdScheme(): String {
        return ClientIdScheme.DID.value
    }

    override fun extractPublicKey(algorithm: RequestSigningAlgorithm, kid: String?): PublicKey {
        val didUrl = getStringValue(authorizationRequestParameters, CLIENT_ID.value)
            ?: throw OpenID4VPExceptions.InvalidData(
                "client_id is not present in authorization request",
                className
            )
        if(kid.isNullOrEmpty()){
            throw OpenID4VPExceptions.InvalidData(
                "keyId is required to extract public key in did client_id_scheme",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        }
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
}

