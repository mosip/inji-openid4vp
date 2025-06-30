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
            ?: throw  OpenID4VPExceptions.PublicKeyExtractionFailed("Public key extraction failed", className)
    }

    private fun extractPublicKeyMultibase(kid: String, didDocument: Map<String, Any>): String? {
        val verificationMethod = didDocument["verificationMethod"] as? List<Map<String, Any>>
        if (verificationMethod != null) {
            for (method in verificationMethod) {
                val id = method["id"] as? String
                val publicKeyMultibase = method["publicKey"] as? String
                if (id == kid && !publicKeyMultibase.isNullOrEmpty()) {
                    return publicKeyMultibase
                }
            }
        }
        return null
    }
}