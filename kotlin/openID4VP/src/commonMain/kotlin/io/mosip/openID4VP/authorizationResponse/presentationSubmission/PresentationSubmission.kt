package io.mosip.openID4VP.authorizationResponse.presentationSubmission

import com.fasterxml.jackson.annotation.JsonProperty

data class PresentationSubmission(
    val id: String,
    @JsonProperty("definition_id") val definitionId: String,
    @JsonProperty("descriptor_map") val descriptorMap: List<DescriptorMap>
)