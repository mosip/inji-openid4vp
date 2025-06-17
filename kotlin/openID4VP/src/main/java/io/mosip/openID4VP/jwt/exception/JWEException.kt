package io.mosip.openID4VP.jwt.exception

sealed class JWEException {

    class UnsupportedKeyExchangeAlgorithm :
        Exception("invalid_request: Required Key exchange algorithm is not supported")

    class JweEncryptionFailure :
        Exception("encryption_failed: JWE Encryption failed")
}