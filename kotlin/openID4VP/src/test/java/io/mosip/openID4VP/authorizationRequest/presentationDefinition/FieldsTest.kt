package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.InvalidInputPattern
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.exceptions.Exceptions.MissingInput

import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class FieldsTest {
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
	fun `should throw invalid input pattern exception for invalid path param prefix`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$-type"]}]}}]}"""
		expectedExceptionMessage =
			"invalid_request: fields->path pattern is not matching with OpenId4VP specification"

		val actualException =
			Assert.assertThrows(InvalidInputPattern::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid_request exception if path param is missing`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{}]}}]}"""
		expectedExceptionMessage = "invalid_request: fields->path param is required"

		val actualException =
			Assert.assertThrows(MissingInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if path param is empty`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":[]}]}}]}"""
		expectedExceptionMessage = "invalid_request: fields->path value cannot be empty or null"

		val actualException =
			Assert.assertThrows(Exceptions.InvalidInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if path param is present but it's value is null`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":null}]}}]}"""
		expectedExceptionMessage = "invalid_request: fields->path value cannot be empty or null"

		val actualException =
			Assert.assertThrows(Exceptions.InvalidInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}
}
