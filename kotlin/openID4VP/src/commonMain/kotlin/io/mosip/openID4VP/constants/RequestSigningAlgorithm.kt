package io.mosip.openID4VP.constants

enum class RequestSigningAlgorithm(val value: String) {
    EdDSA("EdDSA");

    companion object {
        fun fromValue(value: String): RequestSigningAlgorithm? {
            return entries.find { it.value == value }
        }
    }
}