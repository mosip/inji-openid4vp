package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.ResponseMode
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val className = PresentationDefinition::class.simpleName!!
fun parseAndValidatePresentationDefinition(
    authorizationRequestParameters: MutableMap<String, Any>,
    isPresentationDefinitionUriSupported: Boolean
) {
    val hasPresentationDefinition =
        authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION.value)
    val hasPresentationDefinitionUri =
        authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION_URI.value)
    val presentationDefinition: Any?

    when {
        hasPresentationDefinition && hasPresentationDefinitionUri -> {
            throw OpenID4VPExceptions.InvalidData("Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                className)
        }

        hasPresentationDefinition -> {
            presentationDefinition = authorizationRequestParameters[PRESENTATION_DEFINITION.value]
            validate(PRESENTATION_DEFINITION.value, presentationDefinition?.toString(), className)
        }

        hasPresentationDefinitionUri -> {
            if (!isPresentationDefinitionUriSupported) {
                throw  OpenID4VPExceptions.InvalidData("presentation_definition_uri is not support",
                    className,OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_URI)
            }

            val presentationDefinitionUri = getStringValue(
                authorizationRequestParameters,
                PRESENTATION_DEFINITION_URI.value
            )
            validate(PRESENTATION_DEFINITION_URI.value, presentationDefinitionUri, className)
            if (!isValidUrl(presentationDefinitionUri!!)) {
                throw OpenID4VPExceptions.InvalidData("${PRESENTATION_DEFINITION_URI.value} data is not valid", className,OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_REFERENCE)
            }
            val response =
                sendHTTPRequest(
                    url = presentationDefinitionUri,
                    method = HttpMethod.GET
                )
            presentationDefinition = response["body"].toString()
        }

        else -> {
            throw  OpenID4VPExceptions.InvalidData("Either presentation_definition or presentation_definition_uri request param must be present", className)
        }
    }

    val presentationDefinitionObj = when (presentationDefinition) {
        is String -> deserializeAndValidate(
            presentationDefinition,
            PresentationDefinitionSerializer
        )

        is Map<*, *> -> deserializeAndValidate(
            presentationDefinition as Map<String, Any>,
            PresentationDefinitionSerializer
        )

        else -> throw  OpenID4VPExceptions.InvalidData("presentation_definition must be of type String or Map",
            className)
    }

    authorizationRequestParameters[PRESENTATION_DEFINITION.value] = presentationDefinitionObj

    val responseMode = getStringValue(
        authorizationRequestParameters,
        RESPONSE_MODE.value
    )!!

    validateResponseModeForMsoMdocFormat(presentationDefinitionObj, responseMode)
}



private fun validateResponseModeForMsoMdocFormat(presentationDefinitionObj: PresentationDefinition, responseMode: String) {
    val hasMsoMdocFormat = presentationDefinitionObj.format?.containsKey("mso_mdoc") ?: false ||
            presentationDefinitionObj.inputDescriptors.any {
                it.format?.containsKey("mso_mdoc") ?: false
            }

    if (hasMsoMdocFormat && responseMode != ResponseMode.DIRECT_POST_JWT.value) {
        throw OpenID4VPExceptions.InvalidData("When mso_mdoc format is present in presentation definition, response_mode must be direct_post.jwt", className)

    }
}