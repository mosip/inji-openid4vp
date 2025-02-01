package io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler

import io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler.DidUtils.JwtPart.HEADER
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.extractDataJsonFromJwt

object DidUtils {

    enum class JwtPart (val number: Int){
        HEADER(0),
        PAYLOAD(1),
        SIGNATURE(2)
    }
    fun extractKid(jwtToken: String): String? {
        val jwtHeader = extractDataJsonFromJwt(jwtToken, HEADER)
        return jwtHeader["kid"]?.toString()
    }

    fun extractPublicKeyMultibase(kid: String, response: String): String? {
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