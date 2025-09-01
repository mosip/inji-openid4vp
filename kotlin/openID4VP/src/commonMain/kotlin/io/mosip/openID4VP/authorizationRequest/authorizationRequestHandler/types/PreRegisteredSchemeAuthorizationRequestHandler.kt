package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidVerifier
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

    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    init {
        Security.addProvider(provider)
    }
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

    override fun clientIdScheme(): String {
        return ClientIdScheme.PRE_REGISTERED.value
    }

    override fun extractPublicKey(
        algorithm: RequestSigningAlgorithm,
        kid: String?,
    ): PublicKey {
        val clientId = authorizationRequestParameters[CLIENT_ID.value] as String
        if (authorizationRequestParameters.containsKey(CLIENT_METADATA.value))
            throw OpenID4VPExceptions.InvalidData(
                "client_metadata available in Authorization Request, cannot be used to verify the signed Authorization Request",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )

        val verifier = trustedVerifiers.firstOrNull { it.clientId == clientId }
            ?: throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed for keyId = $kid, algorithm: ${algorithm.name}",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        val clientMetadata = verifier.clientMetadata
            ?: throw OpenID4VPExceptions.InvalidData(
                "Public key extraction failed - Either client_metadat not available or jwks not available in pre-registered client_metadata to verify the signed Authorization Request",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )

        val jwks = clientMetadata.jwks
            ?: throw OpenID4VPExceptions.InvalidData(
                "Public key extraction failed - Either client_metadat not available or jwks not available in pre-registered client_metadata to verify the signed Authorization Request",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )

        val keys = jwks.keys

        return filterAndExtractKey(keys, kid, algorithm)
    }

    private fun filterAndExtractKey(
        keys: List<Jwk>,
        kid: String?,
        algorithm: RequestSigningAlgorithm,
    ): PublicKey {
        if (kid != null) {
            val byKid = keys.firstOrNull { it.kid == kid }
                ?: throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                    "Public key extraction failed for kid: $kid",
                    className,
                    OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
                )
            return byKid.toJavaPublicKey()
        }

        val matchingKeys =
            keys.filter { it.supports(RequestSigningAlgorithm.EdDSA) && it.use.equals("sig") }

        val selectedKey = when {
            matchingKeys.size == 0 -> throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "No public key found for algorithm: ${algorithm.name} with signature usage",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )

            matchingKeys.size == 1 -> matchingKeys.first()
            else -> throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed - Multiple ambiguous keys found for ${algorithm.name} with signature usage",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        }

        try {
            return selectedKey.toJavaPublicKey()
        } catch (e: Exception) {
            throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed- ${e.message}",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        }
    }


    private fun Jwk.toJavaPublicKey(): PublicKey {

        return when (kty.uppercase()) {
            "OKP" -> when (crv) {
                "Ed25519" -> buildEd25519PublicKey(x)
                else -> throw OpenID4VPExceptions.PublicKeyResolutionFailed("Unsupported OKP curve: $crv",className)
            }

            else -> throw OpenID4VPExceptions.PublicKeyResolutionFailed("Unsupported key type: $kty",className)
        }
    }

    private fun buildEd25519PublicKey(x: String): PublicKey {
        val publicKeyBytes = decodeFromBase64Url(x)
        val algorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
        val subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, publicKeyBytes)
        val encodedKey = subjectPublicKeyInfo.encoded

        val keySpec = X509EncodedKeySpec(encodedKey)
        val keyFactory = KeyFactory.getInstance("EdDSA", provider)

        return keyFactory.generatePublic(keySpec)
    }


    override fun process(walletMetadata: WalletMetadata): WalletMetadata {
        val updatedWalletMetadata = walletMetadata.copy()
        updatedWalletMetadata.requestObjectSigningAlgValuesSupported = null
        return updatedWalletMetadata
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

}