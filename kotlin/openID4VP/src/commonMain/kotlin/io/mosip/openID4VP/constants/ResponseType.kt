package io.mosip.openID4VP.constants

import com.fasterxml.jackson.annotation.JsonProperty

enum class ResponseType(val value: String)  {
   @JsonProperty("vp_token") VP_TOKEN("vp_token");

    companion object {
        fun fromValue(value: String): ResponseType? {
            return entries.find { it.value == value }
        }
    }
}