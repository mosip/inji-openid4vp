package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

private val className = AuthorizationRequest::class.simpleName!!

fun validateVerifier(
    verifierList: List<Verifier>,
    params: MutableMap<String, Any>,
    shouldValidateVerifier: Boolean
) {
    val clientIdScheme = params["client_id_scheme"]
    val clientId = params["client_id"]
    val redirectUri = params["redirect_uri"]

    when (clientIdScheme) {
        ClientIdScheme.PRE_REGISTERED.value -> {
            if (shouldValidateVerifier) {
                if (verifierList.isEmpty()) {
                    throw Logger.handleException(
                        exceptionType = "EmptyVerifierList",
                        className = AuthorizationRequest.toString()
                    )
                }
                val isValidVerifier = verifierList.any { verifier ->
                    verifier.clientId == clientId &&
                            verifier.responseUris.contains(params["response_uri"])
                }
                if (!isValidVerifier) {
                    throw Logger.handleException(
                        exceptionType = "InvalidVerifierClientID",
                        className = AuthorizationRequest.toString()
                    )
                }
            }
        }
        ClientIdScheme.REDIRECT_URI.value -> {
            if(params["response_uri"]!=null && params["response_mode"] != null){
                throw Logger.handleException(
                    exceptionType = "InvalidQueryParams",
                    className = AuthorizationRequest.toString(),
                    message = "Response Uri and Response mode should not be present, when client id scheme is Redirect Uri"
                )
            }
            if (redirectUri != null && redirectUri != clientId) {
                throw Logger.handleException(
                    exceptionType = "InvalidVerifierRedirectUri",
                    className = AuthorizationRequest.toString(),
                    message = "Client id and redirect_uri value should be equal"
                )
            }
        }


    }
}

fun validateKey(
    key: String,
    params: MutableMap<String, Any>,
    setResponseUri: (String) -> Unit
) {
    val value = getValue(params, key)
    if (value == null || value == "null" || value.isEmpty()) {
        throw Logger.handleException(
            exceptionType = if (params[key] == null) "MissingInput" else "InvalidInput",
            fieldPath = listOf(key),
            className = AuthorizationRequest.toString(),
            fieldType = "String"
        )
    }
    if (key == "response_uri") {
        setResponseUri(value)
    }
}

fun validateUriCombinations(
    redirectUri: String?,
    responseUri: String?,
    responseMode: String?
) {
    val allNil = redirectUri == null && responseUri == null && responseMode == null
    val allPresent = redirectUri != null && responseUri != null && responseMode != null

    if (allNil) {
        throw Logger.handleException(
            exceptionType = "MissingInput",
            fieldPath = listOf("response_uri", "response_mode", "redirect_uri"),
            className = AuthorizationRequest.toString()
        )
    }
    if (allPresent) {
        throw Logger.handleException(
            exceptionType = "InvalidInput",
            fieldPath = listOf("response_uri", "response_mode", "redirect_uri"),
            className = AuthorizationRequest.toString()
        )
    }
}

fun updateRequiredKeys(
    requiredKeys: MutableList<String>,
    redirectUri: String?,
    responseUri: String?,
    responseMode: String?
) {
    if (redirectUri != null && responseUri == null && responseMode == null) {
        requiredKeys.add("redirect_uri")
    }
    if (responseUri != null && responseMode != null && redirectUri == null) {
        requiredKeys.addAll(listOf("response_uri", "response_mode"))
    }
}

fun commonRequiredKeys(params: Map<String, Any>): MutableList<String> {
    val keys = mutableListOf(
        "presentation_definition",
        "client_id",
        "client_id_scheme",
        "response_type",
        "nonce",
        "state"
    )

    if (params.containsKey("client_metadata")) {
        keys.add("client_metadata")
    }
    return keys
}

fun validateAuthorizationRequestParams(
    params: MutableMap<String, Any>, setResponseUri: (String) -> Unit
): MutableMap<String, Any> {
    val baseRequiredFields = commonRequiredKeys(params)
    try {
        validateUriCombinations(
            getValue(params, "redirect_uri"),
            getValue(params, "response_uri"),
            getValue(params, "response_mode"),
        )
        updateRequiredKeys(
            baseRequiredFields,
            getValue(params, "redirect_uri"),
            getValue(params, "response_uri"),
            getValue(params, "response_mode")
        )

        for (key in baseRequiredFields) {
            validateKey(key, params, setResponseUri)
        }
        return params
    } catch (exception: Exception) {
        throw exception
    }
}

fun extractQueryParams(query: String): MutableMap<String, Any> {
    try {
        return query.split("&").map { it.split("=") }
            .associateByTo(mutableMapOf(), { it[0] }, {
                if (it.size > 1) URLDecoder.decode(
                    it[1], StandardCharsets.UTF_8.toString()
                ) else ""
            })
    } catch (exception: Exception) {
        throw Logger.handleException(
            exceptionType = "InvalidQueryParams",
            message = "Exception occurred when extracting the query params from Authorization Request : ${exception.message}",
            className = className
        )
    }
}

fun parseAndValidatePresentationDefinitionInAuthorizationRequest(params: MutableMap<String, Any>): MutableMap<String, Any> {
    val hasPresentationDefinition = params.containsKey("presentation_definition")
    val hasPresentationDefinitionUri = params.containsKey("presentation_definition_uri")
    var presentationDefinitionString = ""

    when {
        hasPresentationDefinition && hasPresentationDefinitionUri -> {
            throw Logger.handleException(
                exceptionType = "InvalidQueryParams",
                message = "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                className = className
            )
        }

        hasPresentationDefinition -> {
            val presentationDefinitionValue = params["presentation_definition"]
            validateRootFieldInvalidScenario(
                "presentation_definition",
                presentationDefinitionValue.toString()
            )
            presentationDefinitionString = presentationDefinitionValue.toString()
        }

        hasPresentationDefinitionUri -> {
            try {
                validateRootFieldInvalidScenario(
                    "presentation_definition_uri",
                    params["presentation_definition_uri"].toString()
                )
                presentationDefinitionString =
                    sendHTTPRequest(
                        url = params["presentation_definition_uri"].toString(),
                        method = HTTP_METHOD.GET
                    )
            } catch (exception: Exception) {
                throw exception
            }
        }

        else -> {
            throw Logger.handleException(
                exceptionType = "InvalidQueryParams",
                message = "Either presentation_definition or presentation_definition_uri request param must be present",
                className = className
            )
        }
    }

    val presentationDefinition: PresentationDefinition =
        deserializeAndValidate((presentationDefinitionString), PresentationDefinitionSerializer)
    params["presentation_definition"] = presentationDefinition

    return params
}

fun parseAndValidateClientMetadataInAuthorizationRequest(params: MutableMap<String, Any>): MutableMap<String, Any> {
    var clientMetadata: ClientMetadata?
    params["client_metadata"]?.let {
        clientMetadata =
            deserializeAndValidate(
                (params["client_metadata"]).toString(),
                ClientMetadataSerializer
            )
        params["client_metadata"] = clientMetadata!!
    }
    return params
}

// TODO: validateRootFieldInvalidScenario is validating only string field type, can method be named accordingly
fun validateRootFieldInvalidScenario(param: String, value: String?) {
    require(value != "null" && validateField(value, "String")) {
        throw Logger.handleException(
            exceptionType = "InvalidInput",
            fieldPath = listOf(param),
            className = className,
            fieldType = "String"
        )
    }
}

fun validateMatchOfAuthRequestObjectAndParams(
    params: MutableMap<String, Any>,
    authorizationRequestObject: MutableMap<String, Any>,
) {
    if (params["client_id"] != authorizationRequestObject["client_id"]) {
        throw AuthorizationRequestExceptions.InvalidData("Client Id mismatch in Authorization Request parameter and the Request Object")
    }
    if (params["client_id_scheme"] != null && params["client_id_scheme"] != authorizationRequestObject["client_id_scheme"]) {
        throw AuthorizationRequestExceptions.InvalidData("Client Id scheme mismatch in Authorization Request parameter and the Request Object")
    }
}

fun getValue(params: Map<String, Any>, key: String): String? {
    return params[key]?.toString()
}

