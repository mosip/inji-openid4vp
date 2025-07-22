package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.constants.FormatType

fun Map<FormatType, UnsignedVPToken>.toJsonString(): String? {
    val formattedMap = this.mapKeys { (key, _) -> key.value }
    val objectMapper = getObjectMapper()

    return objectMapper.writeValueAsString(formattedMap)
}