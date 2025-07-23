package io.mosip.openID4VP.jwt.keyResolver.types

import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import io.mosip.vercred.vcverifier.DidWebResolver

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