package io.mosip.openID4VP.common

import android.util.Log
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions

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
        var fieldPathAsString: String = ""
        fieldPath?.let {
            fieldPathAsString = fieldPath.joinToString("->")
        }
        var exception = Exception()
        when (exceptionType) {
            "MissingInput" -> exception =
                AuthorizationRequestExceptions.MissingInput(fieldPath = fieldPathAsString)

            "InvalidInput" -> exception =
                AuthorizationRequestExceptions.InvalidInput(
                    fieldPath = fieldPathAsString,
                    fieldType = fieldType
                )

            "InvalidInputPattern" -> exception =
                AuthorizationRequestExceptions.InvalidInputPattern(fieldPath = fieldPathAsString)

            "InvalidQueryParams" -> exception =
                AuthorizationRequestExceptions.InvalidQueryParams(message = message ?: "")

            "InvalidVerifierRedirectUri" -> exception =
                AuthorizationRequestExceptions.InvalidVerifierRedirectUri(message = message ?: "")

            "JsonEncodingFailed" -> exception = AuthorizationRequestExceptions.JsonEncodingFailed(
                fieldPath = fieldPathAsString, message = message ?: ""
            )

            "InvalidVerifierClientID" -> exception =
                AuthorizationRequestExceptions.InvalidVerifierClientID()

            "InvalidLimitDisclosure" -> exception =
                AuthorizationRequestExceptions.InvalidLimitDisclosure()

            "DeserializationFailure" -> exception =
                AuthorizationRequestExceptions.DeserializationFailure(
                    fieldPath = fieldPathAsString,
                    message = message ?: ""
                )
                
            "" -> exception =
                Exception("An unexpected exception occurred: exception type: $exceptionType")
        }
        this.error(getLogTag(className), exception)
        return exception
    }
}