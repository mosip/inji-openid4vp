package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.constants.ContentType.APPLICATION_JSON
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidVerifier
import okhttp3.Headers
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPublicKeySpec

private val className = PreRegisteredSchemeAuthorizationRequestHandler::class.simpleName!!

class PreRegisteredSchemeAuthorizationRequestHandler(
    private val trustedVerifiers: List<Verifier>,
    authorizationRequestParameters: MutableMap<String, Any>,
    walletMetadata: WalletMetadata?,
    private val shouldValidateClient: Boolean,
    setResponseUri: (String) -> Unit,
    walletNonce: String,
) : ClientIdSchemeBasedAuthorizationRequestHandler(
    authorizationRequestParameters,
    walletMetadata,
    setResponseUri,
    walletNonce
) {
    override fun validateClientId() {
        if (!shouldValidateClient) return

        val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
        if (trustedVerifiers.none { it.clientId == clientId }) {
            throw InvalidVerifier(
                "Verifier is not trusted by the wallet",
                className
            )
        }
    }

    override fun isRequestUriSupported(): Boolean {
        return true
    }

    override fun isRequestObjectSupported(): Boolean {
        return true
    }

    override fun extractPublicKey(algorithm: RequestSigningAlgorithm, kid: String?): PublicKey {
        val clientMetadata =
            authorizationRequestParameters[CLIENT_METADATA.value] as? ClientMetadata
                ?: throw OpenID4VPExceptions.MissingInput(
                    listOf(CLIENT_METADATA.value),
                    "",
                    className
                )

        val jwks = clientMetadata.jwks
            ?: throw OpenID4VPExceptions.MissingInput(listOf("client_metadata.jwks"), "", className)

        val keys = jwks.keys

        if (kid != null) {
            val byKid = keys.firstOrNull { it.kid == kid }
                ?: throw OpenID4VPExceptions.VerificationFailure(
                    "No JWK found for kid=$kid",
                    className
                )
            return byKid.toJavaPublicKey()
        }

        val matchingKeys = keys.filter { algorithm.matches(it) }

        if (matchingKeys.isEmpty()) {
            throw OpenID4VPExceptions.VerificationFailure(
                "No matching key found for algorithm=${algorithm.name}",
                className
            )
        }

        val sigUseKeys = matchingKeys.filter { it.use.equals("sig", ignoreCase = true) }

        val selectedKey = when {
            sigUseKeys.size == 1 -> sigUseKeys.first()
            sigUseKeys.size > 1 -> throw OpenID4VPExceptions.VerificationFailure(
                "Multiple keys with 'use=sig' found for ${algorithm.name} without 'kid'",
                className
            )

            matchingKeys.size == 1 -> matchingKeys.first()
            else -> throw OpenID4VPExceptions.VerificationFailure(
                "Multiple ambiguous keys found for ${algorithm.name} without 'kid' or unique 'use=sig'",
                className
            )
        }

        return selectedKey.toJavaPublicKey()
    }


    private fun Jwk.toJavaPublicKey(): PublicKey {
        return when (kty.uppercase()) {

            "OKP" -> {
                val xDecoded = decodeFromBase64Url(x)
                val xBigInt = BigInteger(1, xDecoded)
                val namedCurve = NamedParameterSpec(crv)
                val keyFactory = KeyFactory.getInstance(crv)
                keyFactory.generatePublic(XECPublicKeySpec(namedCurve, xBigInt))
            }

            else -> throw IllegalArgumentException("Unsupported key type (kty): $kty")
        }
    }

    override fun process(walletMetadata: WalletMetadata): WalletMetadata {
        val updatedWalletMetadata = walletMetadata.copy()
        updatedWalletMetadata.requestObjectSigningAlgValuesSupported = null
        return updatedWalletMetadata
    }

    override fun getHeadersForAuthorizationRequestUri(): Map<String, String> {
        return mapOf(
            "content-type" to APPLICATION_FORM_URL_ENCODED.value,
            "accept" to APPLICATION_JSON.value
        )
    }

    override fun validateAndParseRequestFields() {
        if (shouldValidateClient) {
            val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
            val responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value)!!

            val preRegisteredVerifier = trustedVerifiers.find { it.clientId == clientId }

            if (preRegisteredVerifier != null) {
                if (!preRegisteredVerifier.responseUris.contains(responseUri)) {
                    throw InvalidVerifier(
                        "Verifier is not trusted by the wallet",
                        className
                    )
                }

                if (preRegisteredVerifier.clientMetadata != null) {
                    if (authorizationRequestParameters.containsKey(CLIENT_METADATA.value)) {
                        throw InvalidVerifier(
                            "client_metadata provided despite pre-registered metadata already existing for the Client Identifier.",
                            className
                        )
                    }
                    authorizationRequestParameters[CLIENT_METADATA.value] =
                        preRegisteredVerifier.clientMetadata
                }
            }
        }

        super.validateAndParseRequestFields()
    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains(APPLICATION_JSON.value, ignoreCase = true) == true
}