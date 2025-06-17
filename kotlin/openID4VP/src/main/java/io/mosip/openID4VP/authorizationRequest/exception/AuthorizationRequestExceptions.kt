package io.mosip.openID4VP.authorizationRequest.exception


sealed class AuthorizationRequestExceptions {

    class InvalidVerifier(message: String) : Exception("invalid_client:$message")

    class InvalidInputPattern(fieldPath: String) :
        Exception("invalid_request: $fieldPath pattern is not matching with OpenId4VP specification")

    class JsonEncodingFailed(fieldPath: String, message: String) :
        Exception("invalid_request: Json encoding failed for $fieldPath due to this error: $message")

    class DeserializationFailure(fieldPath: String, message: String) :
        Exception("invalid_request: Deserializing for $fieldPath failed due to this error: $message")

    class InvalidLimitDisclosure :
        Exception("invalid_request: constraints->limit_disclosure value should be preferred")

    class InvalidQueryParams(message: String) : Exception("invalid_request:$message")

}



