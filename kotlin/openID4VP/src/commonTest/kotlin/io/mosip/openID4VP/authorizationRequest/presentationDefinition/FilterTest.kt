package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlin.test.*

class FilterTest {
	private lateinit var presentationDefinition: String
	private lateinit var expectedExceptionMessage: String
	

	@AfterTest
	fun tearDown() {
		clearAllMocks()
	}

	@Test
	fun `should throw missing input pattern exception if type param is missing`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{}}]}}]}"""
		expectedExceptionMessage = "Missing Input: filter->type param is required"

		val actualException =
			assertFailsWith<OpenID4VPExceptions.MissingInput> {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw missing input exception if pattern param is missing`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{"type":"string"}}]}}]}"""
		expectedExceptionMessage = "Missing Input: filter->pattern param is required"

		val actualException =
			assertFailsWith<OpenID4VPExceptions.MissingInput> {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input pattern exception if type param is empty`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{"type":"","pattern":"MosipCredential"}}]}}]}"""
		expectedExceptionMessage = "Invalid Input: filter->type value cannot be an empty string, null, or an integer"

		val actualException =
			assertFailsWith<OpenID4VPExceptions.InvalidInput>{
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if pattern param is empty`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{"type":"string","pattern":""}}]}}]}"""
		expectedExceptionMessage = "Invalid Input: filter->pattern value cannot be an empty string, null, or an integer"

		val actualException =
			assertFailsWith<OpenID4VPExceptions.InvalidInput>{
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if pattern param is present but it's value is null`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{"type":"string","pattern":null}}]}}]}"""
		expectedExceptionMessage = "Invalid Input: filter->pattern value cannot be an empty string, null, or an integer"

		val actualException =
			assertFailsWith<OpenID4VPExceptions.InvalidInput> {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		assertEquals(expectedExceptionMessage, actualException.message)
	}
}
