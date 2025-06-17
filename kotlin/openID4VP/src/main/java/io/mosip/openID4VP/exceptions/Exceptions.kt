package io.mosip.openID4VP.exceptions

sealed class Exceptions {
    class InvalidData(message: String) : Exception(message)

    class MissingInput(fieldPath: String, message: String) :  Exception(
        if (fieldPath.isNotEmpty()) {
            "invalid_request: $fieldPath param is required"
        } else {
            message
        }
    )

    class InvalidInput(fieldPath: String, fieldType: Any?) :
        Exception(
            "invalid_request: ${
                when (fieldType) {
                    "String" -> "$fieldPath value cannot be an empty string, null, or an integer"
                    "Boolean" -> "$fieldPath value must be either true or false"
                    else -> "$fieldPath value cannot be empty or null"
                }
            }"
        )
}