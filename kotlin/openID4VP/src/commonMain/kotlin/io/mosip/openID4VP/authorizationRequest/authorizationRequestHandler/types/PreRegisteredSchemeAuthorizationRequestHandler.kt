package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.constants.ContentType.APPLICATION_JSON
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidVerifier
import okhttp3.Headers
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Security
import java.security.spec.X509EncodedKeySpec

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

    override fun extractPublicKey(
        algorithm: RequestSigningAlgorithm,
        kid: String?
    ): PublicKey {
        val clientId = authorizationRequestParameters[CLIENT_ID.value] as String
        if(authorizationRequestParameters.containsKey(CLIENT_METADATA.value))
            throw OpenID4VPExceptions.InvalidData("client_metadata available in Authorization Request, cannot be used to verify the signed Authorization Request",
                className)

        val verifier = trustedVerifiers.firstOrNull { it.clientId == clientId }
            ?: throw OpenID4VPExceptions.MissingInput(
                listOf("trusted_verifiers.client_metadata"),
                "No verifier found for client_id=$clientId",
                className
            )

        val clientMetadata = verifier.clientMetadata
            ?: throw OpenID4VPExceptions.MissingInput(
                listOf("trusted_verifiers.client_metadata"),
                "Missing client_metadata for client_id=$clientId",
                className
            )

        val jwks = clientMetadata.jwks
            ?: throw OpenID4VPExceptions.MissingInput(
                listOf("client_metadata.jwks"),
                "Missing jwks for client_id=$clientId",
                className
            )

        val keys = jwks.keys

        // Case 1: If kid is provided, try direct match
        if (kid != null) {
            val byKid = keys.firstOrNull { it.kid == kid }
                ?: throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                    "No JWK found for kid=$kid",
                    className
                )
            return byKid.toJavaPublicKey()
        }

        // Case 2: No kid - match based on algorithm
        val matchingKeys = keys.filter { it.supports(RequestSigningAlgorithm.EdDSA) }

        if (matchingKeys.isEmpty()) {
            throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed for algorithm: ${algorithm.name}. No matching Keys found",
                className
            )
        }

        val sigUseKeys = matchingKeys.filter { it.use.equals("sig") }

        val selectedKey = when {
            sigUseKeys.size == 1 -> sigUseKeys.first()
            sigUseKeys.size > 1 -> throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed.Multiple keys with 'use=sig' found for ${algorithm.name} without 'kid'",
                className
            )
            matchingKeys.size == 1 -> matchingKeys.first()
            else -> throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed.Multiple ambiguous keys found for ${algorithm.name} without 'kid' or unique 'use=sig'",
                className
            )
        }

        try {
            return selectedKey.toJavaPublicKey()
        }
        catch (e:Exception){
            throw OpenID4VPExceptions.PublicKeyResolutionFailed("Public key extraction failed: ${e.message}",
                className)
        }
    }



    private fun Jwk.toJavaPublicKey(): PublicKey {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }

        return when (kty.uppercase()) {
            "OKP" -> when (crv) {
                "Ed25519" -> buildEd25519PublicKey(x)
                else -> throw UnsupportedOperationException("Unsupported OKP curve: $crv")
            }
            else -> throw UnsupportedOperationException("Unsupported key type: $kty")
        }
    }

    private fun buildEd25519PublicKey(x: String): PublicKey {
        val publicKeyBytes = decodeFromBase64Url(x)
        val algorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
        val subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, publicKeyBytes)
        val encodedKey = subjectPublicKeyInfo.encoded

        val keySpec = X509EncodedKeySpec(encodedKey)
        val keyFactory = KeyFactory.getInstance("EdDSA", "BC")

        return keyFactory.generatePublic(keySpec)
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