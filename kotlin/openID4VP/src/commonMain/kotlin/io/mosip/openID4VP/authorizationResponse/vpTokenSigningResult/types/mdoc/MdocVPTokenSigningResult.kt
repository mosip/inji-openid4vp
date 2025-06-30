package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult

class MdocVPTokenSigningResult(
    val docTypeToDeviceAuthentication: Map<String, DeviceAuthentication>
) : VPTokenSigningResult {
    fun validate() {
        docTypeToDeviceAuthentication.map { (_, deviceAuthentication) ->
            deviceAuthentication.validate()
        }
    }
}