package io.mosip.openID4VP.authorizationResponse.presentationSubmission

import com.fasterxml.jackson.annotation.JsonProperty

data class DescriptorMap(
    val id: String,
    val format: String,
    val path: String,
    @JsonProperty("path_nested")
    val pathNested: PathNested? = null,
)

data class PathNested(
    val id: String,
    val format: String,
    val path: String,
)