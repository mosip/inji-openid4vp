package io.mosip.openID4VP.constants

import com.fasterxml.jackson.annotation.JsonProperty

enum class FormatType(val value: String)  {
    @JsonProperty("ldp_vc") LDP_VC("ldp_vc"),
    @JsonProperty("mso_mdoc") MSO_MDOC("mso_mdoc"),
    @JsonProperty("dc+sd-jwt") DC_SD_JWT("dc+sd-jwt"),
    @JsonProperty("vc+sd-jwt") VC_SD_JWT("vc+sd-jwt");

    companion object {
        fun fromValue(value: String): FormatType? {
            return entries.find { it.value == value }
        }
    }
}

enum class VPFormatType(val value: String)  {
    @JsonProperty("ldp_vp") LDP_VP("ldp_vp"),
    @JsonProperty("ldp_vc") LDP_VC("ldp_vc"),
    @JsonProperty("mso_mdoc") MSO_MDOC("mso_mdoc"),
    @JsonProperty("dc+sd-jwt") DC_SD_JWT("dc+sd-jwt"),
    @JsonProperty("vc+sd-jwt") VC_SD_JWT("vc+sd-jwt");

    companion object {
        fun fromValue(value: String): VPFormatType? {
        return entries.find { it.value == value }
        }
    }
}


