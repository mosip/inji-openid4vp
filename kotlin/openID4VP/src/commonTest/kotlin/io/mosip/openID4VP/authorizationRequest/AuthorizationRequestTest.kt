package io.mosip.openID4VP.authorizationRequest


import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.DID
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestFailed
import io.mosip.openID4VP.testData.assertDoesNotThrow
import io.mosip.openID4VP.testData.clientIdOfPreRegistered
import io.mosip.openID4VP.testData.clientIdOfReDirectUriDraft21
import io.mosip.openID4VP.testData.clientIdOfReDirectUriDraft23
import io.mosip.openID4VP.testData.createAuthorizationRequestObject
import io.mosip.openID4VP.testData.createUrlEncodedData
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.requestParams
import io.mosip.openID4VP.testData.requestUrl
import io.mosip.openID4VP.testData.trustedVerifiers
import okhttp3.Headers
import kotlin.test.*


class AuthorizationRequestTest {
    private lateinit var openID4VP: OpenID4VP
    private lateinit var actualException: OpenID4VPExceptions
    private lateinit var expectedExceptionMessage: String
    private var shouldValidateClient = true

    @BeforeTest
    fun setUp() {

        mockkObject(NetworkManagerClient)
        openID4VP = OpenID4VP("test-OpenID4VP")
        

        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/verifier/get-presentation-definition",
                HttpMethod.GET
            )
        } returns mapOf("body" to presentationDefinitionString)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should throw missing input exception if client_id param is missing in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams.minus(CLIENT_ID.value) + mapOf(
            CLIENT_ID_SCHEME.value to DID.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , DID)

        expectedExceptionMessage = "Missing Input: client_id param is required"

        actualException =
            assertFailsWith<OpenID4VPExceptions.MissingInput> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers,  shouldValidateClient,null
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if client_id param is present in Authorization Request but it's value is empty string`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "",
        )
        val encodedAuthorizationRequest = createUrlEncodedData(
            requestParams = authorizationRequestParamsMap,
            clientIdScheme = PRE_REGISTERED,
            verifierSentAuthRequestByReference = false
        )

        expectedExceptionMessage = "Invalid Input: client_id value cannot be an empty string, null, or an integer"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient,null
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if client_id param is present in Authorization Request but it's value is null`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to null,
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , DID)

        expectedExceptionMessage = "Invalid Input: client_id value cannot be an empty string, null, or an integer"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient,null
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if neither presentation_definition nor presentation_definition_uri param present in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams.minus(PRESENTATION_DEFINITION.value) + clientIdOfReDirectUriDraft23
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                false,
                ClientIdScheme.REDIRECT_URI
            )

        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param must be present"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient,null
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if both presentation_definition and presentation_definition_uri request params are present in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val applicableFields = listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap, false, PRE_REGISTERED, applicableFields
            )

        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param can be provided but not both"
        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient,null
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if received client_id is not matching with predefined Verifiers list client_id`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "mock-client-1",
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED)

        val expectedExceptionMessage =
            "Verifier is not trusted by the wallet"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidVerifier> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient,null
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if the url encoded authorization request is invalid`() {

        val encodedAuthorizationRequest ="@#$$#@"

        val expectedExceptionMessage =
            "Exception occurred when extracting the query params from Authorization Request : Index: 1, Size: 1"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidQueryParams> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient,null
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid limit disclosure exception if limit disclosure is present and not matching with predefined values`() {
        val presentationDefinition =
            """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","constraints":{"fields":[{"path":["$.type"]}], "limit_disclosure": "not preferred"}}]}"""

        val authorizationRequestParamsMap = requestParams+ clientIdOfReDirectUriDraft23 + mapOf(
            PRESENTATION_DEFINITION.value to presentationDefinition
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI)

        val expectedExceptionMessage =
            "Invalid Input: constraints->limit_disclosure value should be preferred"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidLimitDisclosure> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient,null
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition & all the other fields are present and valid in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers,shouldValidateClient, null)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should throw error when client_id_scheme is redirect_uri and response_mode is absent`() {

        val authorizationRequestParamsMap = requestParams.minus(RESPONSE_MODE.value) + clientIdOfReDirectUriDraft23
        val applicableFields = listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            REDIRECT_URI.value,
            PRESENTATION_DEFINITION.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value,
            RESPONSE_MODE.value
        )
        val expectedExceptionMessage = "Missing Input: response_mode param is required"

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            false,
            ClientIdScheme.REDIRECT_URI,
            applicableFields
        )

        actualException =
        assertFailsWith<OpenID4VPExceptions.MissingInput> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient,null
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error when client_id_scheme is redirect_uri and redirect_uri and client_id is different`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "redirect_uri:wrong-client-id"
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI
            )

        val expectedExceptionMessage = "response_uri should be equal to client_id for given client_id_scheme"
        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient,null
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition_uri & all the other fields are present and valid in Authorization Request`() {


        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered

        val applicableFields =  listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , PRE_REGISTERED, applicableFields
            )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers,shouldValidateClient, null)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should throw error if presentation_definition_uri is invalid in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft23 + mapOf(PRESENTATION_DEFINITION_URI.value to "test-data")
        val applicableFields = listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI, applicableFields
            )

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers, false,null)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_REFERENCE, actualException.errorCode)
        assertEquals("presentation_definition_uri data is not valid",actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if all the fields are valid in Authorization Request and clientValidation is not needed`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft23
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI
            )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers, false,null)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should get presentation definition  by making api call if presentation_definition_uri is present in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                CLIENT_ID_SCHEME.value,
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value,
                CLIENT_METADATA.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, applicationFields)
        )


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED, applicationFields)


        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

    }

    @Test
    fun `should add default client id scheme as pre-registered if not present in authorization request`() {
        val authorizationRequestParamsMap = requestParams +  mapOf(
            CLIENT_ID.value to "mock-client",
        )
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                CLIENT_ID_SCHEME.value,
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value,
                CLIENT_METADATA.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, applicationFields)
        )


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED, applicationFields)

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

    }

    @Test
    fun `should return Authorization Request for redirect uri scheme when passed by value`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft23

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI,)

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
    }

    @Test
    fun `should throw error if response mode is not present in the authorization request`() {
        val authorizationRequestParamsMap = requestParams.minus(RESPONSE_MODE.value) + clientIdOfReDirectUriDraft23

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI,)

        expectedExceptionMessage = "Missing Input: response_mode param is required"
        actualException = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error if response mode is not valid in the authorization request`() {
        val authorizationRequestParamsMap = requestParams+ clientIdOfReDirectUriDraft23 + mapOf(RESPONSE_MODE.value to "wrong input")

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI,)

        expectedExceptionMessage = "Given response_mode is not supported"
        actualException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error if redirect uri field is present in the authorization request`() {
        val authorizationRequestParamsMap = requestParams+ clientIdOfReDirectUriDraft23 + mapOf(REDIRECT_URI.value to "wrong input")

        val applicableFields = listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value,
            REDIRECT_URI.value,
            PRESENTATION_DEFINITION.value
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI,applicableFields)

        expectedExceptionMessage = "redirect_uri should not be present for given response_mode"
        actualException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error if api call of presentation_definition_uri fails in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered + mapOf(PRESENTATION_DEFINITION_URI.value to "https://mock-verifier.com/verifier/get-presentation-definition-1")
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                CLIENT_ID_SCHEME.value,
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value,
                CLIENT_METADATA.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, applicationFields)
        )


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED, applicationFields)


        assertFailsWith<NetworkRequestFailed> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
    }

    @Test
    fun `should throw error client id is not present in trusted verifier for pre registered client id scheme in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                CLIENT_ID_SCHEME.value,
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value,
                CLIENT_METADATA.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, applicationFields)
        )


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED, applicationFields)

        assertFailsWith<OpenID4VPExceptions.InvalidVerifier> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                emptyList(),
                shouldValidateClient = true
            )
        }
    }

    @Test
    fun `should return Authorization Request with client_id_scheme not null for draft 21 version`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft21 + mapOf(CLIENT_ID_SCHEME.value to ClientIdScheme.REDIRECT_URI.value)
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI, draftVersion = 21)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers,shouldValidateClient, null)
        assertEquals(REDIRECT_URI.value, actualValue.clientIdScheme)
    }
    @Test
    fun `should return Authorization Request with client_id_scheme not null for draft 21 version for pre-registered client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered + mapOf(CLIENT_ID_SCHEME.value to PRE_REGISTERED.value)
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED, draftVersion = 21)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers,shouldValidateClient, null)
        assertEquals(PRE_REGISTERED.value, actualValue.clientIdScheme)
    }

    @Test
    fun `should return Authorization Request with validations of pre-registered client_id_scheme if the client_id_scheme is not present in client id for draft 23`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft21 + mapOf(CLIENT_ID_SCHEME.value to ClientIdScheme.REDIRECT_URI.value)
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI, draftVersion = 21)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers,shouldValidateClient, null)
        assertEquals(clientIdOfReDirectUriDraft21[CLIENT_ID.value], actualValue.responseUri)
    }
}

