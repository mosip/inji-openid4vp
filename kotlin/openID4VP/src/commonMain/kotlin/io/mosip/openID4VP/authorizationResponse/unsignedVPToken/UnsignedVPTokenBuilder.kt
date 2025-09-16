package io.mosip.openID4VP.authorizationResponse.unsignedVPToken

import io.mosip.openID4VP.authorizationResponse.mapping.CredentialInputDescriptorMapping

internal interface UnsignedVPTokenBuilder {
    fun build(credentialInputDescriptorMappings : List<CredentialInputDescriptorMapping>) : Pair<Any?, UnsignedVPToken>
}