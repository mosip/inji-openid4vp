package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.authorizationRequest
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.clientMetadataMap
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.setField
import io.mosip.openID4VP.testData.ldpvpTokenSigningResults
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import io.mosip.openID4VP.testData.ldpVPToken
import io.mosip.openID4VP.testData.mdocvpTokenSigningResults
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.mdocVPToken
import io.mosip.openID4VP.testData.proof
import io.mosip.openID4VP.testData.unsignedLdpVPToken
import io.mosip.openID4VP.testData.unsignedMdocVPToken
import io.mosip.openID4VP.testData.unsignedVPTokens
import org.junit.After
import org.junit.Assert
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull

class AuthorizationResponseHandlerTest {
    private val ldpVcList1 = listOf(
        ldpCredential1,
        ldpCredential2
    )
    private val ldpVcList2 = listOf(
        ldpCredential2
    )
    private val mdocVcList = listOf(mdocCredential)
    private val selectedLdpVcCredentialsList = mapOf(
        "456" to mapOf(
            FormatType.LDP_VC to ldpVcList1
        ), "789" to mapOf(
            FormatType.LDP_VC to ldpVcList2
        )
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(
            FormatType.MSO_MDOC to mdocVcList
        )
    )

    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler

    @Before
    fun setUp() {
        authorizationResponseHandler = AuthorizationResponseHandler()
        setField(authorizationResponseHandler, "credentialsMap", selectedLdpVcCredentialsList)

         val unsignedLdpVPTokenForReflection =  UnsignedLdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = listOf("credential1", "credential2", "credential3"),
            id = "649d581c-f291-4969-9cd5-2c27385a348f",
            holder = "",
        )

        val unsignedVPTokens =
            mapOf(FormatType.LDP_VC to unsignedLdpVPTokenForReflection)

        setField(authorizationResponseHandler, "unsignedVPTokens", unsignedVPTokens)

        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }

        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        mockkObject(DateUtil)
        every { DateUtil.formattedCurrentDateTime() } returns "2024-02-13T10:00:00Z"

        mockkObject(NetworkManagerClient)
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

//    construction of vpTokens for signing

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC and MSO_MDOC formats`() {

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build() } returns unsignedLdpVPToken

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build() } returns unsignedMdocVPToken

        val expectedUnsignedVPToken = mapOf(
            FormatType.LDP_VC to unsignedLdpVPToken,
            FormatType.MSO_MDOC to unsignedMdocVPToken
        )

        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap =   selectedMdocCredentialsList+selectedLdpVcCredentialsList,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
        )

        assertNotNull(unsignedVPToken)
        assertEquals(2, unsignedVPToken.size)
        assertEquals(expectedUnsignedVPToken[FormatType.LDP_VC], unsignedVPToken[FormatType.LDP_VC])
        assertEquals(expectedUnsignedVPToken[FormatType.MSO_MDOC], unsignedVPToken[FormatType.MSO_MDOC])
    }


    @Test
    fun `should throw error during construction of data for signing when selected Credentials is empty`() {
        val actualException =
            assertThrows(OpenID4VPExceptions.InvalidData::class.java) {
                authorizationResponseHandler.constructUnsignedVPToken(
                    credentialsMap = mapOf(),
                    authorizationRequest = authorizationRequest,
                    responseUri = "https://mock-verifier.com",
                )
            }
        Assert.assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        Assert.assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            actualException.message
        )
    }

    // Sharing of Verifiable Presentation

    @Test
    fun `should make network call to verifier responseUri with the vp_token, presentation_submission and state successfully`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")
        val authorizationResponse = AuthorizationResponse(
            presentationSubmission = PresentationSubmission(
                id = "649d581c-f291-4969-9cd5-2c27385a348f",
                definitionId = "649d581c-f891-4969-9cd5-2c27385a348f",
                descriptorMap = listOf(
                    DescriptorMap(
                        id = "456",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "456",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[0]"
                        )
                    ),
                    DescriptorMap(
                        id = "456",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "456",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[1]"
                        )
                    ),
                    DescriptorMap(
                        id = "789",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "789",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[2]"
                        )
                    )
                )
            ),
            vpToken = VPTokenType.VPTokenElement(
                value = LdpVPToken(
                    context = listOf("https://www.w3.org/2018/credentials/v1"),
                    type = listOf("VerifiablePresentation"),
                    verifiableCredential = listOf("credential1", "credential2", "credential3"),
                    id = "649d581c-f291-4969-9cd5-2c27385a348f",
                    holder = "",
                    proof = proof
                )
            ),
            state = "fsnC8ixCs6mWyV+00k23Qg=="
        )
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = ldpvpTokenSigningResults,
            responseUri = authorizationRequest.responseUri!!
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequest.responseUri!!,
                method = HttpMethod.POST,
                bodyParams = authorizationResponse.toJsonEncodedMap(),
                headers = expectedHeaders
            )
        }
    }

    @Test
    fun `should make network call to verifier responseUri with encrypted body successfully when both mdoc vc is being shared`() {
        mockkConstructor(LdpVPTokenBuilder::class)
        every { anyConstructed<LdpVPTokenBuilder>().build() } returns ldpVPToken

        mockkConstructor(MdocVPTokenBuilder::class)
        every { anyConstructed<MdocVPTokenBuilder>().build() } returns mdocVPToken

        setField(authorizationResponseHandler, "credentialsMap", selectedLdpVcCredentialsList + selectedMdocCredentialsList)
        setField(authorizationResponseHandler, "unsignedVPTokens", unsignedVPTokens)



        every {
            NetworkManagerClient.sendHTTPRequest(
                authorizationRequestForResponseModeJWT.responseUri!!,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")

        mockkConstructor(JWEHandler::class)
        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns "eytyiewr.....jewjr"
        val expectedBodyWithAuthResponseParams = mapOf(
            "response" to "eytyiewr.....jewjr"
        )
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequestForResponseModeJWT,
            vpTokenSigningResults = ldpvpTokenSigningResults + mdocvpTokenSigningResults,
            responseUri = authorizationRequestForResponseModeJWT.responseUri!!
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequestForResponseModeJWT.responseUri!!,
                method = HttpMethod.POST,
                bodyParams = expectedBodyWithAuthResponseParams,
                headers = expectedHeaders
            )
        }
    }

    @Test
    fun `should make network call to verifier responseUri with the vp_token, presentation_submission successfully`() {
        val authorizationRequestWithoutStateProperty = AuthorizationRequest(
            clientId = "https://mock-verifier.com",
            responseType = "vp_token",
            responseMode = "direct_post",
            presentationDefinition = deserializeAndValidate(
                presentationDefinitionMap,
                PresentationDefinitionSerializer
            ),
            responseUri = "https://mock-verifier.com",
            redirectUri = null,
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = null,
            clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer)
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequestWithoutStateProperty,
            vpTokenSigningResults = ldpvpTokenSigningResults,
            responseUri = authorizationRequest.responseUri!!
        )

        val authorizationResponse = AuthorizationResponse(
            presentationSubmission = PresentationSubmission(
                id = "649d581c-f291-4969-9cd5-2c27385a348f",
                definitionId = "649d581c-f891-4969-9cd5-2c27385a348f",
                descriptorMap = listOf(
                    DescriptorMap(
                        id = "456",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "456",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[0]"
                        )
                    ),
                    DescriptorMap(
                        id = "456",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "456",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[1]"
                        )
                    ),
                    DescriptorMap(
                        id = "789",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "789",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[2]"
                        )
                    )
                )
            ),
            vpToken = VPTokenType.VPTokenElement(
                value = LdpVPToken(
                    context = listOf("https://www.w3.org/2018/credentials/v1"),
                    type = listOf("VerifiablePresentation"),
                    verifiableCredential = listOf("credential1", "credential2", "credential3"),
                    id = "649d581c-f291-4969-9cd5-2c27385a348f",
                    holder = "",
                    proof = proof
                )
            ),
            state = null
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequest.responseUri!!,
                method = HttpMethod.POST,
                bodyParams = authorizationResponse.toJsonEncodedMap(),
                headers = expectedHeaders
            )
        }
    }

    @Test
    fun `should throw error when response type is not supported`() {
        val authorizationRequestWithNonVPTokenResponseType = AuthorizationRequest(
            clientId = "https://mock-verifier.com",
            responseType = "code",
            responseMode = "direct_post",
            presentationDefinition = deserializeAndValidate(
                presentationDefinitionMap,
                PresentationDefinitionSerializer
            ),
            responseUri = "https://mock-verifier.com",
            redirectUri = null,
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = "fsnC8ixCs6mWyV+00k23Qg==",
            clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer)
        )

        val actualException =
            assertThrows(OpenID4VPExceptions.InvalidData::class.java) {
                authorizationResponseHandler.shareVP(
                    authorizationRequest = authorizationRequestWithNonVPTokenResponseType,
                    vpTokenSigningResults = ldpvpTokenSigningResults,
                    responseUri = authorizationRequest.responseUri!!
                )
            }
        Assert.assertEquals(OpenID4VPErrorCodes.VP_FORMATS_NOT_SUPPORTED, actualException.errorCode)
        Assert.assertEquals(
            "Provided response_type - code is not supported",
            actualException.message
        )
    }

    @Test
    fun `should throw error when a credential format entry is not available in unsignedVPTokens but available in vpTokenSigningResults`() {
        setField(
            authorizationResponseHandler,
            "unsignedVPTokens",
            emptyMap<FormatType, UnsignedVPToken>()
        )
        val actualException =
            assertThrows(OpenID4VPExceptions.InvalidData::class.java) {
                authorizationResponseHandler.shareVP(
                    authorizationRequest = authorizationRequest,
                    vpTokenSigningResults = ldpvpTokenSigningResults,
                    responseUri = authorizationRequest.responseUri!!
                )
            }
        Assert.assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        Assert.assertEquals(
            "unable to find the related credential format - LDP_VC in the unsignedVPTokens map",
            actualException.message
        )
    }


}