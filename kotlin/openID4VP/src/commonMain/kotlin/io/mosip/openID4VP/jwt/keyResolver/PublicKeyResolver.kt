package io.mosip.openID4VP.jwt.keyResolver

fun interface PublicKeyResolver {
     //TODO: should return publicKey instead of String once multiple signature support is added
     fun resolveKey(header: Map<String, Any>): String
}