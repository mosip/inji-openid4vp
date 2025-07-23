package io.mosip.openID4VP.jwt.keyResolver.types

import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.HEADER
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.PAYLOAD
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.SIGNATURE
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import io.mosip.vercred.vcverifier.DidWebResolver
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

private val className = DidPublicKeyResolver::class.simpleName!!

class DidPublicKeyResolver(private val didUrl: String) : PublicKeyResolver {

    //TODO: should create public key object from the string based on signature algorithm
    override fun resolveKey(header: Map<String, Any>): String {
        val didResponse = try {
            DidWebResolver(didUrl).resolve()
        }catch (e: Exception){
            throw OpenID4VPExceptions.PublicKeyResolutionFailed(e.message.toString(), className)
        }

        val kid = header["kid"]?.toString()
            ?: throw OpenID4VPExceptions.KidExtractionFailed("KID extraction from DID document failed",
                className)

        return extractPublicKeyMultibase(kid, didResponse)
            ?: throw  OpenID4VPExceptions.PublicKeyExtractionFailed("Public key extraction failed for kid: $kid", className)
    }

    private fun extractPublicKeyMultibase(kid: String, didDocument: Map<String, Any>): String? {
        val verificationMethods = didDocument["verificationMethod"] as? List<Map<String, Any>> ?: return null

        for (method in verificationMethods) {
            if (method["id"] == kid) {

                if (!SUPPORTED_PUBLIC_KEY_TYPES.any { method.containsKey(it) }) {
                    throw OpenID4VPExceptions.UnsupportedPublicKeyType(className)
                }

                val publicKeyMultibase = method["publicKeyMultibase"] as? String
                if (publicKeyMultibase.isNullOrEmpty()) {
                    throw OpenID4VPExceptions.InvalidData("publicKeyMultibase cannot be null or empty", className)
                }

                return publicKeyMultibase
            }
        }
        return null
    }

    companion object {
        val SUPPORTED_PUBLIC_KEY_TYPES = listOf("publicKeyMultibase")
    }
}