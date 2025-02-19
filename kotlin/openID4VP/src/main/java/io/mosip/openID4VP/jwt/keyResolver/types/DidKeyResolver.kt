package io.mosip.openID4VP.jwt.keyResolver.types

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.jwt.keyResolver.KeyResolver
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

class DidKeyResolver(private val didUrl: String) : KeyResolver {

    companion object {
        private val className = DidKeyResolver::class.simpleName ?: "DidHandler"
        private const val RESOLVER_API = "https://resolver.identity.foundation/1.0/identifiers/"
    }

    //TODO: should create public key object from the string based on signature algorithm
    override fun resolveKey(header: Map<String, Any>): String {
        val url = "$RESOLVER_API${didUrl}"
        val response = sendHTTPRequest(url, HTTP_METHOD.GET)
        val didResponse = response["body"].toString()

        val kid = header["kid"]?.toString()
            ?: throw Logger.handleException(
                exceptionType = "KidExtractionFailed",
                className = className,
                message = "KID extraction from DID document failed"
            )
        return extractPublicKeyMultibase(kid, didResponse)
            ?: throw Logger.handleException(
                exceptionType = "PublicKeyExtractionFailed",
                className = className,
                message = "Public key extraction failed"
            )
    }

    private fun extractPublicKeyMultibase(kid: String, response: String): String? {
        val rootJson = convertJsonToMap(response)
        val didDocument = rootJson["didDocument"] as Map<*, *>
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