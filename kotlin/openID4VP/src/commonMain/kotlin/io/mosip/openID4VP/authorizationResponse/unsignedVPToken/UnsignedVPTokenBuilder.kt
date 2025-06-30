package io.mosip.openID4VP.authorizationResponse.unsignedVPToken

internal interface UnsignedVPTokenBuilder {
    fun build(): Map<String, Any>
}