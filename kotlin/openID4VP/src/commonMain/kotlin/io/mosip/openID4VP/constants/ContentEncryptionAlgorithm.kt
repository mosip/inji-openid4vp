package io.mosip.openID4VP.constants

enum class ContentEncryptionAlgorithm(val value: String) {
    A256GCM("A256GCM");

    companion object {
        fun fromValue(value: String): ContentEncryptionAlgorithm? {
            return entries.find { it.value == value }
        }
    }
}