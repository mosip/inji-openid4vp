package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.ResponseMode.DIRECT_POST_JWT
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.json.Json
import org.assertj.core.api.Assertions.assertThat
import kotlin.test.*

class PresentationDefinitionTest {

    private lateinit var presentationDefinition: String
    private lateinit var expectedExceptionMessage: String

   

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should throw missing input exception if id param is missing`() {
        presentationDefinition =
            """{"input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        expectedExceptionMessage = "Missing Input: presentation_definition->id param is required"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.MissingInput> {
                deserializeAndValidate(
                    presentationDefinition,
                    PresentationDefinitionSerializer
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw missing input exception if input_descriptors param is missing`() {
        presentationDefinition = """{"id":"pd_123"}"""
        expectedExceptionMessage = "Missing Input: presentation_definition->input_descriptors param is required"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.MissingInput> {
                deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if id param value is empty`() {
        presentationDefinition =
            """{"id":"","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        expectedExceptionMessage =
            "Invalid Input: presentation_definition->id value cannot be an empty string, null, or an integer"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if input_descriptor param value is empty`() {
        presentationDefinition = """{"id":"pd_123","input_descriptors":[]}"""
        expectedExceptionMessage =
            "Invalid Input: presentation_definition->input_descriptors value cannot be empty or null"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if input_descriptor param value is present but it's value is null`() {
        presentationDefinition = """{"id":"pd_123","input_descriptors":null}"""
        expectedExceptionMessage =
            "Invalid Input: presentation_definition->input_descriptors value cannot be empty or null"

        val actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage,actualException.message)
    }

    @Test
    fun `should throw error if presentation definition uri is not supported by wallet`() {
        val authorizationRequestParam: MutableMap<String, Any> = mutableMapOf(
            PRESENTATION_DEFINITION_URI.value to "https://mock-verifier.com/verifier/get-presentation-definition",
            RESPONSE_MODE.value to DIRECT_POST_JWT.value
        )

        val expectedExceptionMessage = "presentation_definition_uri is not support"

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidatePresentationDefinition(authorizationRequestParam, false)
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_URI, exception.errorCode)
        assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should serialize PresentationDefinition correctly with all fields`() {
        val presentationDefinition = PresentationDefinition(
            id = "test-id",
            inputDescriptors = listOf(
                InputDescriptor(
                    id = "descriptor-id",
                    name = "Test Descriptor",
                    purpose = "Testing",
                    constraints = Constraints(
                        fields = listOf(
                            Fields(
                                id = "id",
                                path = listOf("$.type"),
                                filter = Filter(type = "type", pattern = "pattern")
                            )
                        )
                    )
                )
            ),
            name = "Test Definition",
            purpose = "Unit Testing",
            format = mapOf(
                "mso_mdoc" to mapOf("alg" to listOf("EC")),
                "ldp_vc" to mapOf("proof_type" to listOf("Ed25519Signature2018"))
            )
        )

        val json = Json.encodeToString(PresentationDefinitionSerializer, presentationDefinition)
        val decodedPresentationDefinition = Json.decodeFromString(PresentationDefinitionSerializer, json)

        assertThat(decodedPresentationDefinition)
            .usingRecursiveComparison()
            .isEqualTo(presentationDefinition)
    }
}
