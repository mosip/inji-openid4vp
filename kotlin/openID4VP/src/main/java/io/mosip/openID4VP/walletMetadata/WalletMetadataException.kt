sealed class ValidationError(message: String) : Exception(message) {

    object InvalidJSON : ValidationError("Invalid JSON format.")

    class MissingRequiredField(field: String) :
        ValidationError("Missing required field: $field.")

    class ExtraField(field: String) :
        ValidationError("Extra field detected: $field.")

    override fun toString(): String {
        return message ?: "Unknown Validation Error"
    }
}
