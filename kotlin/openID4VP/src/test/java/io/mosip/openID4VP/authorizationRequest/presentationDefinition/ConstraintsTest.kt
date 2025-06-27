package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
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
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","format":{"ldp_vc":{"proof_type":["RsaSignature2018"]}},"constraints":{"fields":[{"path":["$.type"]}],"limit_disclosure": "not preferred"}}]}"""

		val actualException =
			Assert.assertThrows(OpenID4VPExceptions.InvalidLimitDisclosure::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		val expectedExceptionMessage =
			"Invalid Input: constraints->limit_disclosure value should be preferred"

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}
}