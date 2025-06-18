package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.exceptions.Exceptions.MissingInput

import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class FilterTest {
	private lateinit var presentationDefinition: String
	private lateinit var expectedExceptionMessage: String

	@Before
	fun setUp() {
		mockkStatic(Log::class)
		every { Log.e(any(), any()) } answers {
			val tag = arg<String>(0)
			val msg = arg<String>(1)
			println("Error: logTag: $tag | Message: $msg")
			0
		}
	}

	@After
	fun tearDown() {
		clearAllMocks()
	}

	@Test
	fun `should throw invalid_request pattern exception if type param is missing`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{}}]}}]}"""
		expectedExceptionMessage = "invalid_request: filter->type param is required"

		val actualException =
			Assert.assertThrows(MissingInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid_request exception if pattern param is missing`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{"type":"string"}}]}}]}"""
		expectedExceptionMessage = "invalid_request: filter->pattern param is required"

		val actualException =
			Assert.assertThrows(MissingInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid_request pattern exception if type param is empty`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{"type":"","pattern":"MosipCredential"}}]}}]}"""
		expectedExceptionMessage = "invalid_request: filter->type value cannot be an empty string, null, or an integer"

		val actualException =
			Assert.assertThrows(Exceptions.InvalidInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid_request exception if pattern param is empty`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{"type":"string","pattern":""}}]}}]}"""
		expectedExceptionMessage = "invalid_request: filter->pattern value cannot be an empty string, null, or an integer"

		val actualException =
			Assert.assertThrows(Exceptions.InvalidInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid_request exception if pattern param is present but it's value is null`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$.type"], "filter":{"type":"string","pattern":null}}]}}]}"""
		expectedExceptionMessage = "invalid_request: filter->pattern value cannot be an empty string, null, or an integer"

		val actualException =
			Assert.assertThrows(Exceptions.InvalidInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}
}
