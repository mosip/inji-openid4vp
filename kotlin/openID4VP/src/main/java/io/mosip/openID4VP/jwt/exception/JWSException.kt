package io.mosip.openID4VP.jwt.exception

sealed class JWSException {

    class PublicKeyExtractionFailed(message: String) : Exception("invalid_request: $message")

    class KidExtractionFailed(message: String) : Exception("invalid_request: $message")

    class PublicKeyResolutionFailed(message: String) : Exception("invalid_request: $message")

    class InvalidSignature(message: String) : Exception("invalid_request: $message")

    class VerificationFailure(message: String) : Exception("invalid_request: $message")
}