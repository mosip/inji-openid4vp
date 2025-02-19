package io.mosip.openID4VP.common

import android.util.Log
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.jwt.exception.JWTVerificationException

object Logger {
    private var traceabilityId: String? = null

    fun setTraceabilityId(traceabilityId: String) {
        this.traceabilityId = traceabilityId
    }

    fun getLogTag(className: String): String {
        return "INJI-OpenID4VP : class name - $className | traceID - ${this.traceabilityId ?: ""}"
    }

    fun error(logTag: String, exception: Exception) {
        Log.e(logTag, exception.message!!)
    }

    fun handleException(
        exceptionType: String,
        message: String? = null,
        fieldPath: List<String>? = null,
        className: String,
        fieldType: Any? = null
    ): Exception {
        var fieldPathAsString = ""
        fieldPath?.let {
            fieldPathAsString = fieldPath.joinToString("->")
        }
        val exception: Exception = when (exceptionType) {

            "InvalidInput" -> AuthorizationRequestExceptions.InvalidInput(
                fieldPath = fieldPathAsString,
                fieldType = fieldType
            )
            "DeserializationFailure" -> AuthorizationRequestExceptions.DeserializationFailure(
                fieldPath = fieldPathAsString,
                message = message ?: ""
            )
            "JsonEncodingFailed" -> AuthorizationRequestExceptions.JsonEncodingFailed(
                fieldPath = fieldPathAsString, message = message ?: ""
            )
            "MissingInput" -> AuthorizationRequestExceptions.MissingInput(fieldPath = fieldPathAsString)

            "InvalidInputPattern" -> AuthorizationRequestExceptions.InvalidInputPattern(fieldPath = fieldPathAsString)

            "InvalidQueryParams" -> AuthorizationRequestExceptions.InvalidQueryParams(message = message ?: "")

            "InvalidVerifierRedirectUri" -> AuthorizationRequestExceptions.InvalidVerifierRedirectUri(message = message ?: "")

            "InvalidVerifier" -> AuthorizationRequestExceptions.InvalidVerifier()

            "InvalidLimitDisclosure" -> AuthorizationRequestExceptions.InvalidLimitDisclosure()

            "InvalidClientIdScheme" -> AuthorizationRequestExceptions.InvalidClientIdScheme(message = message ?: "")

            "InvalidResponseMode" -> AuthorizationRequestExceptions.InvalidResponseMode(message = message ?: "")

            "InvalidData" -> AuthorizationRequestExceptions.InvalidData(message = message ?: "")

            "KidExtractionFailed" -> JWTVerificationException.KidExtractionFailed(message = message ?: "")

            "PublicKeyExtractionFailed" -> JWTVerificationException.PublicKeyExtractionFailed(message = message ?: "")

            "InvalidSignature" -> JWTVerificationException.InvalidSignature(message = message ?: "")

            else -> Exception("An unexpected exception occurred: exception type: $exceptionType")
        }
        this.error(getLogTag(className), exception)
        return exception
    }
}