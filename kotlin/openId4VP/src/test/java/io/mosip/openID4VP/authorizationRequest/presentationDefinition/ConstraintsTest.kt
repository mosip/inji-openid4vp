package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class ConstraintsTest {

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
	fun `should throw invalid limit disclosure exception if limit disclosure is present and not matching with predefined values`() {
		val presentationDefinition =
			"{\"id\":\"pd_123\",\"input_descriptors\":[{\"id\":\"id_123\",\"constraints\":{\"fields\":[{\"path\":[\"\$.type\"]}],\"limit_disclosure\": \"not preferred\"}}]}"

		val expectedExceptionMessage =
			"Invalid Input: limit_disclosure value should be either required or preferred"

		val actualException =
			Assert.assertThrows(AuthorizationRequestExceptions.InvalidLimitDisclosure::class.java) {
				validatePresentationDefinition(presentationDefinition)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)

	}
}