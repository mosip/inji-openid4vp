package io.mosip.openID4VP.constants

enum class ResponseType(val value: String)  {
    VP_TOKEN("vp_token");

    companion object {
        fun fromValue(value: String): ResponseType? {
            return entries.find { it.value == value }
        }
    }
}