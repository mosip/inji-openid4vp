package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenArray
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenElement
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.generateNonce
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory

private val className = AuthorizationResponseHandler::class.java.simpleName

/**
 * This class also has V1 methods for handling backward compatibility.
 * The previous version of the OpenID4VP library supported only Ldp VC and had a simplier structure.
 */

internal class AuthorizationResponseHandler {
    private lateinit var credentialsMap: Map<String, Map<FormatType, List<Any>>>
    private lateinit var unsignedVPTokens: Map<FormatType, Map<String, Any>>
    private val walletNonce = generateNonce(16)

    fun constructUnsignedVPToken(
        credentialsMap: Map<String, Map<FormatType, List<Any>>>,
        holderId: String,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        signatureSuite: String
    ): Map<FormatType, UnsignedVPToken> {
        if (credentialsMap.isEmpty()) {
            throw OpenID4VPExceptions.InvalidData("Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.", className)
        }
        this.credentialsMap = credentialsMap
        this.unsignedVPTokens =
            createUnsignedVPTokens(authorizationRequest, responseUri, holderId, signatureSuite)

        return unsignedVPTokens.mapValues { it.value["unsignedVPToken"] as UnsignedVPToken }
    }

    fun shareVP(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>,
        responseUri: String,
    ): String {
        val authorizationResponse: AuthorizationResponse = createAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults
        )

        return sendAuthorizationResponse(
            authorizationResponse = authorizationResponse,
            responseUri = responseUri,
            authorizationRequest = authorizationRequest
        )
    }

    //Create authorization response based on the response_type parameter in authorization response
    private fun createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>,
    ): AuthorizationResponse {
        when (authorizationRequest.responseType) {
            ResponseType.VP_TOKEN.value -> {
                val credentialFormatIndex: MutableMap<FormatType, Int> = mutableMapOf()
                val vpToken = createVPToken(
                    vpTokenSigningResults,
                    authorizationRequest,
                    credentialFormatIndex
                )
                val presentationSubmission: PresentationSubmission = createPresentationSubmission(
                    authorizationRequest = authorizationRequest,
                    credentialFormatIndex = credentialFormatIndex
                )
                return AuthorizationResponse(
                    presentationSubmission = presentationSubmission,
                    vpToken = vpToken,
                    state = authorizationRequest.state
                )
            }

            else -> throw  OpenID4VPExceptions.InvalidData("Provided response_type - ${authorizationRequest.responseType} is not supported", className,OpenID4VPErrorCodes.VP_FORMATS_NOT_SUPPORTED)
        }
    }

    //Send authorization response to verifier based on the response_mode parameter in authorization request
    private fun sendAuthorizationResponse(
        authorizationResponse: AuthorizationResponse,
        responseUri: String,
        authorizationRequest: AuthorizationRequest,
    ): String {
        return ResponseModeBasedHandlerFactory.get(authorizationRequest.responseMode!!)
            .sendAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                url = responseUri,
                authorizationResponse = authorizationResponse,
                walletNonce = walletNonce,
            )
    }

    private fun createVPToken(
        vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>,
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): VPTokenType {
        val vpTokens: MutableList<VPToken> = mutableListOf()

        vpTokenSigningResults.entries.forEachIndexed { index, (credentialFormat, vpTokenSigningResult) ->
            vpTokens.add(
                VPTokenFactory(
                    vpTokenSigningResult = vpTokenSigningResult,
                    vpTokenSigningPayload = unsignedVPTokens[credentialFormat]?.get("vpTokenSigningPayload")
                        ?: throw OpenID4VPExceptions.InvalidData("unable to find the related credential format - $credentialFormat in the unsignedVPTokens map", className),
                    nonce = authorizationRequest.nonce
                ).getVPTokenBuilder(credentialFormat).build()
            )
            credentialFormatIndex[credentialFormat] = index
        }

        val vpToken: VPTokenType = vpTokens.takeIf { it.size == 1 }
            ?.let { VPTokenElement(it[0]) }
            ?: VPTokenArray(vpTokens)

        return vpToken
    }

    private fun createPresentationSubmission(
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): PresentationSubmission {
        val descriptorMap = createInputDescriptor(credentialFormatIndex)

        return PresentationSubmission(
            id = UUIDGenerator.generateUUID(),
            definitionId = authorizationRequest.presentationDefinition.id,
            descriptorMap = descriptorMap,
        )
    }

    private fun createInputDescriptor(credentialFormatIndex: MutableMap<FormatType, Int>): List<DescriptorMap> {
        //In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        //and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        val isMultipleVPTokens: Boolean = credentialFormatIndex.keys.size > 1
        val formatTypeToCredentialIndex: MutableMap<FormatType, Int> = mutableMapOf()

        val descriptorMappings =
            credentialsMap.toSortedMap().map { (inputDescriptorId, formatMap) ->
                formatMap.flatMap { (credentialFormat, credentials) ->
                    val vpTokenIndex = credentialFormatIndex[credentialFormat]

                    credentials.map {
                        val rootLevelPath = when {
                            isMultipleVPTokens -> "$[$vpTokenIndex]"
                            else -> "$"
                        }
                        val credentialIndex =
                            (formatTypeToCredentialIndex[credentialFormat] ?: -1) + 1
                        val vpFormat: String
                        var pathNested: PathNested? = null
                        when (credentialFormat) {
                            FormatType.LDP_VC -> {
                                val relativePath = "$.${LdpVPToken.INTERNAL_PATH}[$credentialIndex]"
                                vpFormat = VPFormatType.LDP_VP.value
                                pathNested = PathNested(
                                    id = inputDescriptorId,
                                    format = credentialFormat.value,
                                    path = relativePath
                                )
                            }

                            FormatType.MSO_MDOC -> {
                                vpFormat = VPFormatType.MSO_MDOC.value
                            }
                        }
                        formatTypeToCredentialIndex[credentialFormat] = credentialIndex

                        DescriptorMap(
                            id = inputDescriptorId,
                            format = vpFormat,
                            path = rootLevelPath,
                            pathNested = pathNested
                        )
                    }
                }

            }
        return descriptorMappings.flatten()
    }

    private fun createUnsignedVPTokens(
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        holderId: String,
        signatureSuite: String
    ): Map<FormatType, Map<String, Any>> {
        val groupedVcs: Map<FormatType, List<Any>> = credentialsMap.toSortedMap().values
            .flatMap { it.entries }
            .groupBy({ it.key }, { it.value }).mapValues { (_, lists) ->
                lists.flatten()
            }

        // group all formats together, call specific creator and pass the grouped credentials
        return groupedVcs.mapValues { (format, credentialsArray) ->
            when (format) {
                FormatType.LDP_VC -> {
                    UnsignedLdpVPTokenBuilder(
                        verifiableCredential = credentialsArray,
                        id = UUIDGenerator.generateUUID(),
                        holder = holderId,
                        challenge = authorizationRequest.nonce,
                        domain = authorizationRequest.clientId,
                        signatureSuite = signatureSuite
                    ).build()
                }

                FormatType.MSO_MDOC -> {
                    UnsignedMdocVPTokenBuilder(
                        mdocCredentials = credentialsArray as List<String>,
                        clientId = authorizationRequest.clientId,
                        responseUri = responseUri,
                        verifierNonce = authorizationRequest.nonce,
                        mdocGeneratedNonce = walletNonce
                    ).build()
                }
            }
        }
    }

    @Deprecated("This method supports constructing VP token for LDP VC without canonicalization of the data sent for signing")
    fun constructUnsignedVPTokenV1(
        verifiableCredentials: Map<String, List<String>>,
        authorizationRequest: AuthorizationRequest,
        responseUri: String
    ): String{

        val transformedCredentials = verifiableCredentials.mapValues { (_, credentials) ->
            mapOf(FormatType.LDP_VC to credentials)
        }
        constructUnsignedVPToken(
            credentialsMap = transformedCredentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUri,
            holderId = "",
            signatureSuite = "Ed25519Signature2020"
        )
        val unsignedLdpVPToken =
            unsignedVPTokens[FormatType.LDP_VC]?.get("vpTokenSigningPayload").let {
                it as LdpVPToken
            }.copy(proof = null)

        return encodeToJsonString(unsignedLdpVPToken, "unsignedLdpVPToken", className)
    }

    @Deprecated("This method only supports sharing LDP VC in direct post response mode")
    fun shareVPV1(
        vpResponseMetadata: VPResponseMetadata,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
    ): String {
        try {
            vpResponseMetadata.validate()
            var pathIndex = 0
            val flattenedCredentials = credentialsMap.mapValues { (_, formatMap) ->
                formatMap.values.first()
            }
            val descriptorMap = mutableListOf<DescriptorMap>()
            flattenedCredentials.forEach { (inputDescriptorId, vcs) ->
                vcs.forEach { _ ->
                    descriptorMap.add(
                        DescriptorMap(
                            inputDescriptorId,
                            "ldp_vp",
                            "$.verifiableCredential[${pathIndex++}]"
                        )
                    )
                }
            }
            val presentationSubmission = PresentationSubmission(
                UUIDGenerator.generateUUID(),
                authorizationRequest.presentationDefinition.id,
                descriptorMap
            )
            val unsignedLdpVPToken =
                unsignedVPTokens[FormatType.LDP_VC]?.get("vpTokenSigningPayload") as VPTokenSigningPayload
            val vpToken = unsignedLdpVPToken.apply {
                holder = vpResponseMetadata.publicKey
                proof!!.verificationMethod = vpResponseMetadata.publicKey
                proof.jws = vpResponseMetadata.jws
            }
            val authorizationResponse = AuthorizationResponse(
                presentationSubmission = presentationSubmission,
                vpToken = VPTokenElement(vpToken),
                state = authorizationRequest.state
            )
            return sendAuthorizationResponse(
                authorizationResponse = authorizationResponse,
                responseUri = responseUri,
                authorizationRequest = authorizationRequest
            )
        } catch (exception: Exception) {
            throw exception
        }
    }

}