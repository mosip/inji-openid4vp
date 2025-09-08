package io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken

@JsonSerialize(using = SdJwtVPTokenSerializer::class)
data class SdJwtVPToken(
    val value: String
) : VPToken

class SdJwtVPTokenSerializer : JsonSerializer<SdJwtVPToken>() {
    override fun serialize(
        value: SdJwtVPToken,
        gen: JsonGenerator,
        serializers: SerializerProvider
    ) {
        gen.writeString(value.value)
    }
}
