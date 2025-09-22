package io.mosip.openID4VP.exceptions

import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR_DESCRIPTION
import java.util.logging.Level
import java.util.logging.Logger

sealed class OpenID4VPExceptions(
    val errorCode: String,
    override val message: String,
    val className: String
) : Exception("$errorCode : $message") {

    init {
        Logger.getLogger(className).log(Level.SEVERE,"ERROR [$errorCode] - $message | Class: $className")
    }

    companion object {
        fun error(message: String, className: String) {
            Logger.getLogger(className).log(Level.SEVERE,"ERROR : $message | Class: $className")
        }
    }

    fun toErrorResponse(): MutableMap<String, String> {
        return mutableMapOf(
            ERROR to errorCode,
            ERROR_DESCRIPTION to message
        )
    }

    // Authorization Exceptions

    class InvalidVerifier(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_CLIENT, message, className)

    class AccessDenied(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.ACCESS_DENIED, message, className)

    class InvalidTransactionData(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA, message, className)

    class InvalidInputPattern(fieldPath: Any, className: String) :
        OpenID4VPExceptions(
            OpenID4VPErrorCodes.INVALID_REQUEST,
            "Invalid Input Pattern: ${
                if (fieldPath is List<*> && fieldPath.isNotEmpty()) fieldPath.joinToString("->") else fieldPath
            } pattern is not matching with OpenId4VP specification",
            className
        )


    class JsonEncodingFailed(fieldPath: Any, errorMessage: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, "Json encoding failed for $fieldPath due to this error: $errorMessage", className)

    class DeserializationFailure(fieldPath: Any, errorMessage: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, "Deserializing for $fieldPath failed due to this error: $errorMessage", className)

    class InvalidLimitDisclosure(className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, "Invalid Input: constraints->limit_disclosure value should be preferred", className)

    class InvalidQueryParams(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, message, className)


    // General Exceptions
    class InvalidData(
        message: String,
        className: String,
        code: String? = null
    ) : OpenID4VPExceptions(
        errorCode = code ?: OpenID4VPErrorCodes.INVALID_REQUEST,
        message = message,
        className = className
    )


    class MissingInput(fieldPath: Any, message: String, className: String) :
        OpenID4VPExceptions(
            OpenID4VPErrorCodes.INVALID_REQUEST,
            when {
                fieldPath is String && fieldPath.isNotEmpty() ->
                    "Missing Input: $fieldPath param is required"
                fieldPath is List<*> && fieldPath.isNotEmpty() ->
                    "Missing Input: ${fieldPath.joinToString("->")} param is required"
                else -> message
            },
            className
        )

    class InvalidInput(fieldPath: Any, fieldType: Any?, className: String) :
        OpenID4VPExceptions(
            OpenID4VPErrorCodes.INVALID_REQUEST,
            "Invalid Input: ${
                when (fieldType) {
                    "String" -> "${if (fieldPath is List<*> && fieldPath.isNotEmpty()) fieldPath.joinToString("->") else fieldPath} value cannot be an empty string, null, or an integer"
                    "Boolean" -> "${if (fieldPath is List<*> && fieldPath.isNotEmpty()) fieldPath.joinToString("->") else fieldPath} value must be either true or false"
                    else -> "${if (fieldPath is List<*> && fieldPath.isNotEmpty()) fieldPath.joinToString("->") else fieldPath} value cannot be empty or null"
                }
            }",
            className
        )


    // JWS Exceptions

    class PublicKeyExtractionFailed(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, message, className)

    class UnsupportedPublicKeyType(className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, "Unsupported Public Key type. Supported: publicKeyMultibase", className)

    class KidExtractionFailed(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, message, className)

    class PublicKeyResolutionFailed(message: String, className: String, code: String? = OpenID4VPErrorCodes.INVALID_REQUEST) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, message, className)

    class InvalidSignature(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, message, className)

    class VerificationFailure(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, message, className)

    // JWE Exceptions

    class UnsupportedKeyExchangeAlgorithm(className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, "Required Key exchange algorithm is not supported", className)

    class JweEncryptionFailure(className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, "JWE Encryption failed", className)


    // Exception while sending error to Verifier
    class ErrorDispatchFailure(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.ERROR_DISPATCH_FAILURE, "Failed to send error to verifier: $message", className)

    //fallback
    class GenericFailure(
        override val message: String,
        className: String,
    ) : OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_REQUEST, message, className)
}