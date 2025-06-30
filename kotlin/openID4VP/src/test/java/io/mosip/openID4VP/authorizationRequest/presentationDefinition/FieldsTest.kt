package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

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
			"Invalid Input Pattern: fields->path pattern is not matching with OpenId4VP specification"

		val actualException =
			Assert.assertThrows(OpenID4VPExceptions.InvalidInputPattern::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		Assert.assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw missing input exception if path param is missing`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{}]}}]}"""
		expectedExceptionMessage = "Missing Input: fields->path param is required"

		val actualException =
			Assert.assertThrows(OpenID4VPExceptions.MissingInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		Assert.assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if path param is empty`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":[]}]}}]}"""
		expectedExceptionMessage = "Invalid Input: fields->path value cannot be empty or null"

		val actualException =
			Assert.assertThrows(OpenID4VPExceptions.InvalidInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		Assert.assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if path param is present but it's value is null`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":null}]}}]}"""
		expectedExceptionMessage = "Invalid Input: fields->path value cannot be empty or null"

		val actualException =
			Assert.assertThrows(OpenID4VPExceptions.InvalidInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}
		Assert.assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}
}
