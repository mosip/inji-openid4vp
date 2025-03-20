package io.mosip.openID4VP.authorizationResponse

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.VPTokenForSigning
import io.mosip.openID4VP.constants.FormatType

fun Map<FormatType, VPTokenForSigning>.toJsonString(): String? {
    val formattedMap = this.mapKeys { (key, _) -> key.value }
    val objectMapper = jacksonObjectMapper()

    return objectMapper.writeValueAsString(formattedMap)
}