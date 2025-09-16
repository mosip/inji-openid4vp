package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.mapping.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenArray
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenElement
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPTokenBuilder
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory

private val className = AuthorizationResponseHandler::class.java.simpleName

/**
 * This class also has V1 methods for handling backward compatibility.
 * The previous version of the OpenID4VP library supported only Ldp VC and had a simpler structure.
 */

internal class AuthorizationResponseHandler {
    private lateinit var unsignedVPTokenResults: Map<FormatType, Pair<Any?, UnsignedVPToken>>
    private lateinit var walletNonce: String
    private lateinit var formatToCredentialInputDescriptorMapping: Map<FormatType, List<CredentialInputDescriptorMapping>>

    fun constructUnsignedVPToken(
        credentialsMap: Map<String, Map<FormatType, List<Any>>>,
        holderId: String?,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        signatureSuite: String?,
        nonce: String
    ): Map<FormatType, UnsignedVPToken> {

        val containsLdpVc = credentialsMap.any { (_, formatMap) ->
            formatMap.containsKey(FormatType.LDP_VC)
        }

        if (containsLdpVc) {
            require(!holderId.isNullOrEmpty()) {
                OpenID4VPExceptions.InvalidData(
                    "Holder ID cannot be null or empty for LDP VC format",
                    className
                )
            }
            require(!signatureSuite.isNullOrEmpty()) {
                OpenID4VPExceptions.InvalidData(
                    "Signature Suite cannot be null or empty for LDP VC format",
                    className
                )
            }
        }

        return createUnsignedVPToken(
            credentialsMap,
            holderId,
            authorizationRequest,
            responseUri,
            signatureSuite,
            nonce
        )
    }

    private fun createUnsignedVPToken(
        credentialsMap: Map<String, Map<FormatType, List<Any>>>,
        holderId: String?,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        signatureSuite: String?,
        nonce: String
    ): Map<FormatType, UnsignedVPToken> {
        walletNonce = nonce
        if (credentialsMap.isEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
                className
            )
        }
        this.unsignedVPTokenResults =
            createUnsignedVPTokens(
                authorizationRequest,
                responseUri,
                holderId,
                signatureSuite,
                credentialsMap
            )

        return unsignedVPTokenResults.mapValues { it.value.second }
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
                val (vpToken, presentationSubmission) = createVPTokenAndPresentationSubmission(
                    vpTokenSigningResults,
                    authorizationRequest,
                    unsignedVPTokenResults,
                    formatToCredentialInputDescriptorMapping
                )

                return AuthorizationResponse(
                    presentationSubmission = presentationSubmission,
                    vpToken = vpToken,
                    state = authorizationRequest.state
                )
            }

            else -> throw OpenID4VPExceptions.InvalidData(
                "Provided response_type - ${authorizationRequest.responseType} is not supported",
                className
            )
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

    private fun createVPTokenAndPresentationSubmission(
        vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>,
        authorizationRequest: AuthorizationRequest,
        unsignedVPTokenResults: Map<FormatType, Pair<Any?, UnsignedVPToken>>,
        formatToCredentialInputDescriptorMapping: Map<FormatType, List<CredentialInputDescriptorMapping>>
    ): Pair<VPTokenType, PresentationSubmission> {
        if (unsignedVPTokenResults.keys != vpTokenSigningResults.keys) {
            throw OpenID4VPExceptions.InvalidData(
                message = "VPTokenSigningResult not provided for the required formats",
                className = className
            )
        }

        val finalVpTokens : MutableList<VPToken> = mutableListOf()
        val finalDescriptorMappings : MutableList<DescriptorMap> = mutableListOf()
        var rootIndex = 0


        formatToCredentialInputDescriptorMapping.forEach{ (credentialFormat, credentialInputDescriptorMappings) ->
            val vpTokenSigningResult = (vpTokenSigningResults[credentialFormat]
                ?: throw OpenID4VPExceptions.InvalidData(
                    "unable to find the related credential format - $credentialFormat in the vpTokenSigningResults map",
                    className
                ))
            val unsignedVPTokenResult = unsignedVPTokenResults[credentialFormat]
                ?: throw OpenID4VPExceptions.InvalidData(
                    "unable to find the related credential format - $credentialFormat in the unsignedVPTokenResults map",
                    className
                )
            val vpTokenBuilder = VPTokenFactory(
                vpTokenSigningResult = vpTokenSigningResult,
                unsignedVPTokens = unsignedVPTokenResult.second,
                vpTokenSigningPayload = unsignedVPTokenResult.first ?: mapOf("k1" to "k2"),
                nonce = authorizationRequest.nonce,
                uuid = "null"
            ).getVPTokenBuilder(credentialFormat)

            val (vpTokens, descriptorMaps, nextRootIndex) = vpTokenBuilder.build(
                credentialInputDescriptorMappings,
                unsignedVPTokenResult,
                vpTokenSigningResult,
                rootIndex
            )
            finalVpTokens.addAll(vpTokens)
            finalDescriptorMappings.addAll(descriptorMaps)

            rootIndex = nextRootIndex
        }

        val vpToken = (finalVpTokens.takeIf { it.size == 1 }
            ?.let { VPTokenElement(it[0]) }
            ?: VPTokenArray(finalVpTokens))

        sanitizeDescriptorMap(finalDescriptorMappings, finalVpTokens.size == 1)
        val presentationSubmission = PresentationSubmission(
            id = UUIDGenerator.generateUUID(),
            definitionId = authorizationRequest.presentationDefinition.id,
            descriptorMap = finalDescriptorMappings,
        )

        return Pair(vpToken, presentationSubmission)
    }

    private fun sanitizeDescriptorMap(
        descriptorMaps: MutableList<DescriptorMap>,
        isSingleVPToken: Boolean
    ) {
        //In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        //and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        if (isSingleVPToken) {
            descriptorMaps.forEach { descriptorMap ->
                val updatedRootPath = descriptorMap.path.replace(Regex("""\[\d+]"""), "")
                val updatedDescriptorMap = descriptorMap.copy(path = updatedRootPath, pathNested = descriptorMap.pathNested)
                descriptorMaps[descriptorMaps.indexOf(descriptorMap)] = updatedDescriptorMap
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun createUnsignedVPTokens(
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        holderId: String?,
        signatureSuite: String?,
        credentialsMap: Map<String, Map<FormatType, List<Any>>>
    ): Map<FormatType, Pair<Any?, UnsignedVPToken>> {
        createFormatToCredentialInputDescriptorMapping(credentialsMap)

        // group all formats together, call specific creator and pass the grouped credentials
        return this.formatToCredentialInputDescriptorMapping.mapValues { (format, credentialInputDescriptorMappings) ->
            when (format) {
                FormatType.LDP_VC -> {
                    UnsignedLdpVPTokenBuilder(
                        verifiableCredential = credentialInputDescriptorMappings,
                        id = UUIDGenerator.generateUUID(),
                        holder = holderId!!,
                        challenge = authorizationRequest.nonce,
                        domain = authorizationRequest.clientId,
                        signatureSuite = signatureSuite!!
                    ).build(credentialInputDescriptorMappings)
                }

                FormatType.MSO_MDOC -> {
                    UnsignedMdocVPTokenBuilder(
                        mdocCredentials = credentialInputDescriptorMappings as List<String>,
                        clientId = authorizationRequest.clientId,
                        responseUri = responseUri,
                        verifierNonce = authorizationRequest.nonce,
                        mdocGeneratedNonce = walletNonce
                    ).build(credentialInputDescriptorMappings)
                }

                FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> {
                    UnsignedSdJwtVPTokenBuilder(
                        sdJwtCredentials = credentialInputDescriptorMappings as List<String>,
                        nonce = authorizationRequest.nonce,
                        clientId = authorizationRequest.clientId
                    ).build(credentialInputDescriptorMappings)
                }
            }
        }
    }

    @Deprecated("This method supports constructing VP token for LDP VC without canonicalization of the data sent for signing")
    fun constructUnsignedVPTokenV1(
        verifiableCredentials: Map<String, List<String>>,
        authorizationRequest: AuthorizationRequest,
        responseUri: String
    ): String {

        val transformedCredentials = verifiableCredentials.mapValues { (_, credentials) ->
            mapOf(FormatType.LDP_VC to credentials)
        }
        createUnsignedVPToken(
            credentialsMap = transformedCredentials,
            holderId = "",
            authorizationRequest = authorizationRequest,
            responseUri = responseUri,
            signatureSuite = "Ed25519Signature2020",
            nonce = walletNonce
        )
        val unsignedLdpVPToken =
            unsignedVPTokenResults[FormatType.LDP_VC]?.first.let {
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

            val flattenedCredentials: Map<String, List<Any>> = this.formatToCredentialInputDescriptorMapping.values.flatten() .groupBy({ it.inputDescriptorId }, { it.credential })
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
            val (ldpVPTokenPayload: Any?, _) = unsignedVPTokenResults[FormatType.LDP_VC]
                ?: throw OpenID4VPExceptions.InvalidData(
                    "LDP VC format not found in the unsignedVPTokenResults map",
                    className
                )
            val vpToken = (ldpVPTokenPayload as VPTokenSigningPayload).apply {
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

    private fun createFormatToCredentialInputDescriptorMapping(matchingCredentials: Map<String, Map<FormatType, List<Any>>>) {
        val formatToCredentialInputDescriptorMapping =
            mutableMapOf<FormatType, MutableList<CredentialInputDescriptorMapping>>()

        for ((inputDescriptorId, formatCredentialMap) in matchingCredentials) {
            for ((format, credentialsArray) in formatCredentialMap) {
                credentialsArray.forEach { credential ->
                    val mapping = CredentialInputDescriptorMapping(
                        credential = credential,
                        format = format,
                        inputDescriptorId = inputDescriptorId
                    )
                    formatToCredentialInputDescriptorMapping.getOrPut(format) { mutableListOf() }
                        .add(mapping)
                }
            }
        }
        this.formatToCredentialInputDescriptorMapping = formatToCredentialInputDescriptorMapping
    }

}