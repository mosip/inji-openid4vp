package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import kotlinx.serialization.Serializable

@Serializable
enum class LimitDisclosure(val value: String) {
    PREFERRED("preferred");
}