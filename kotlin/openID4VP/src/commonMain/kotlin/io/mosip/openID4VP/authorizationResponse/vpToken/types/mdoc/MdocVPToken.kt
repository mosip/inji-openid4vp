package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken

@JsonSerialize(using = MdocVPTokenSerializer::class)
data class MdocVPToken(
    val base64EncodedDeviceResponse: String
) : VPToken

class MdocVPTokenSerializer : JsonSerializer<MdocVPToken>() {
    override fun serialize(
        value: MdocVPToken,
        jsonGenerator: JsonGenerator,
        serializers: SerializerProvider
    ) {
        jsonGenerator.writeString(value.base64EncodedDeviceResponse)
    }
}