package io.mosip.openID4VP.authorizationResponse.mapping

import io.mosip.openID4VP.constants.FormatType

internal class CredentialInputDescriptorMapping(
    val format: FormatType,
    val credential: Any,
    val inputDescriptorId: String
) {
    var identifier: String? = null
    var nestedPath: String? = null
}

