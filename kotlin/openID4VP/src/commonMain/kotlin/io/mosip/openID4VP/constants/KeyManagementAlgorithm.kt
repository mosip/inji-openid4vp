package io.mosip.openID4VP.constants

import com.fasterxml.jackson.annotation.JsonProperty

enum class KeyManagementAlgorithm(val value: String) {
    @JsonProperty("ECDH-ES") ECDH_ES("ECDH-ES");

    companion object {
        fun fromValue(value: String): KeyManagementAlgorithm? {
            return entries.find { it.value == value }
        }
    }
}