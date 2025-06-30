package io.mosip.openID4VP.responseModeHandler

import io.mosip.openID4VP.constants.ResponseMode.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.types.DirectPostJwtResponseModeHandler
import io.mosip.openID4VP.responseModeHandler.types.DirectPostResponseModeHandler

private val className = ResponseModeBasedHandlerFactory::class.simpleName!!

object ResponseModeBasedHandlerFactory {
    fun get(responseMode: String): ResponseModeBasedHandler =
        when(responseMode) {
            DIRECT_POST.value -> DirectPostResponseModeHandler()
            DIRECT_POST_JWT.value -> DirectPostJwtResponseModeHandler()
            else ->
                throw  OpenID4VPExceptions.InvalidData("Given response_mode is not supported", className)
        }
}