package io.mosip.openID4VP.authorizationResponse

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.constants.ResponseType
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationResponse.models.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.models.vpToken.types.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.VPTokenForSigning
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVPTokenForSigning
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenArray
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenElement
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.networkManager.CONTENT_TYPES
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import okhttp3.internal.toImmutableMap

private val className = AuthorizationResponseHandler::class.java.simpleName

class AuthorizationResponseHandler {
    private lateinit var credentialsMap: Map<String, Map<FormatType, List<String>>>
    private lateinit var vpTokensForSigning: Map<FormatType, VPTokenForSigning>

    fun constructVPTokenForSigning(
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        holder: String
    ): Map<FormatType, VPTokenForSigning> {
        this.credentialsMap = credentialsMap
        if (credentialsMap.isEmpty()) {
            throw Logger.handleException(
                exceptionType = "EmptyCredentialsList",
                className = className,
                message = "The Wallet did not have the requested Credentials to satisfy the Authorization Request."
            )
        }
        this.vpTokensForSigning = createVPTokenForSigning(credentialsMap, holder)
        return this.vpTokensForSigning
    }

    fun shareVP(
        authorizationRequest: AuthorizationRequest,
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        responseUri: String,
    ): String {
        val authorizationResponse: Map<String, String> = createAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpResponsesMetadata = vpResponsesMetadata,
            credentialsMap = this.credentialsMap,
            vpTokensForSigning = this.vpTokensForSigning
        )

        return sendAuthorizationResponse(
            authorizationResponse = authorizationResponse,
            responseUri = responseUri
        )
    }

    //Create authorization response based on the response_type parameter in authorization response
    private fun createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        vpTokensForSigning: Map<FormatType, VPTokenForSigning>,
    ): Map<String, String> {
        when (authorizationRequest.responseType) {
            ResponseType.VP_TOKEN.value -> {
                val credentialFormatIndex: MutableMap<FormatType, Int> = mutableMapOf()
                val vpToken = createVPToken(
                    vpResponsesMetadata,
                    authorizationRequest,
                    vpTokensForSigning,
                    credentialFormatIndex
                )
                val presentationSubmission: PresentationSubmission = createPresentationSubmission(
                    credentialsMap = credentialsMap,
                    authorizationRequest = authorizationRequest,
                    credentialFormatIndex = credentialFormatIndex
                )
                return buildMap {
                    put("vp_token", jacksonObjectMapper().writeValueAsString(vpToken))
                    put(
                        "presentation_submission",
                        jacksonObjectMapper().writeValueAsString(presentationSubmission)
                    )
                    authorizationRequest.state?.let { put("state", it) }
                }.toImmutableMap()
            }

            else -> throw Logger.handleException(
                exceptionType = "UnsupportedResponseType",
                className = className,
                message = "Provided response_type ${authorizationRequest.responseType} is not supported"
            )
        }
    }

    //Send authorization response to verifier based on the response_mode parameter in authorization request
    private fun sendAuthorizationResponse(
        authorizationResponse: Map<String, String>,
        responseUri: String,
    ): String {
        val response = sendHTTPRequest(
            url = responseUri,
            method = HTTP_METHOD.POST,
            bodyParams = authorizationResponse,
            headers = mapOf("Content-Type" to CONTENT_TYPES.APPLICATION_FORM_URL_ENCODED.value)
        )
        return response["body"].toString()
    }

    private fun createVPToken(
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        authorizationRequest: AuthorizationRequest,
        vpTokensForSigning: Map<FormatType, VPTokenForSigning>,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): VPTokenType {
        val vpTokens: MutableList<VPToken> = mutableListOf()

        var count = 0
        for ((credentialFormat, vpResponseMetadata) in vpResponsesMetadata) {
            val vpToken = VPTokenFactory(
                vpResponseMetadata = vpResponseMetadata,
                vpTokenForSigning = vpTokensForSigning[credentialFormat] ?: throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className
                ),
                nonce = authorizationRequest.nonce
            ).getVPTokenBuilder(credentialFormat).build()

            vpTokens.add(vpToken)
            credentialFormatIndex[credentialFormat] = count
            count++
        }

        val vpToken: VPTokenType = vpTokens.takeIf { it.size == 1 }
            ?.let { VPTokenElement(it[0]) }
            ?: VPTokenArray(vpTokens)

        return vpToken
    }

    private fun createPresentationSubmission(
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): PresentationSubmission {
        val descriptorMap = createInputDescriptor(credentialsMap, credentialFormatIndex)
        val presentationDefinitionId =
            (authorizationRequest.presentationDefinition as PresentationDefinition).id

        return PresentationSubmission(
            id = UUIDGenerator.generateUUID(),
            definitionId = presentationDefinitionId,
            descriptorMap = descriptorMap,
        )
    }

    private fun createInputDescriptor(
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): List<DescriptorMap> {
        //In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        //and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        val multipleVpTokens: Boolean = credentialFormatIndex.keys.size > 1
        val formatTypeToCredentialIndex: MutableMap<FormatType, Int> = mutableMapOf()

        val descriptorMappings =
            credentialsMap.toSortedMap().map { (inputDescriptorId, formatMap) ->
                formatMap.flatMap { (format, credentials) ->
                    val vpTokenIndex = credentialFormatIndex[format]

                    credentials.map {
                        val rootLevelPath = when {
                            multipleVpTokens -> "$[$vpTokenIndex]"
                            else -> "$"
                        }
                        val credentialIndex = (formatTypeToCredentialIndex[format] ?: -1) + 1
                        val relativePath = when (format) {
                            FormatType.LDP_VC -> "$.${LdpVPToken.INTERNAL_PATH}[$credentialIndex]"
                        }
                        formatTypeToCredentialIndex[format] = credentialIndex

                        DescriptorMap(
                            id = inputDescriptorId,
                            format = format.value,
                            path = rootLevelPath,
                            pathNested = PathNested(
                                id = inputDescriptorId,
                                format = format.value,
                                path = relativePath
                            )
                        )
                    }
                }

            }
        return descriptorMappings.flatten()
    }

    private fun createVPTokenForSigning(
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        holder: String
    ): Map<FormatType, VPTokenForSigning> {
        val groupedVcs: Map<FormatType, List<String>> = credentialsMap.toSortedMap().values
            .flatMap { it.entries }
            .groupBy({ it.key }, { it.value }).mapValues { (_, lists) ->
                lists.flatten()
            }

        // group all formats together, call specific creator and pass the grouped credentials
        return groupedVcs.mapValues { (format, credentialsArray) ->
            when (format) {
                FormatType.LDP_VC -> LdpVPTokenForSigning(
                    verifiableCredential = credentialsArray,
                    id = UUIDGenerator.generateUUID(),
                    holder = holder
                )
            }
        }
    }
}