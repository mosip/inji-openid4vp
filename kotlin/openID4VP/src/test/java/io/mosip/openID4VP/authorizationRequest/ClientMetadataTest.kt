package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.dto.Verifier
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class ClientMetadataTest {
	private lateinit var presentationDefinition: String
	private lateinit var expectedExceptionMessage: String
	private lateinit var actualException: Exception
	private lateinit var openID4VP: OpenID4VP
	private lateinit var trustedVerifiers: List<Verifier>
	private lateinit var encodedAuthorizationRequestUrl: String
	private var shouldValidateClient = true

	@Before
	fun setUp() {
		mockkStatic(Log::class)
		every { Log.e(any(), any()) } answers {
			val tag = arg<String>(0)
			val msg = arg<String>(1)
			println("Error: logTag: $tag | Message: $msg")
			0
		}
		openID4VP = OpenID4VP("test-OpenID4VP")
		presentationDefinition =
			"""{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","format":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"constraints":{"fields":[{"path":["$.type"]}]}}]}"""
		trustedVerifiers = listOf(
			Verifier(
				"https://verifier.env1.net", listOf(
					"https://verifier.env1.net/responseUri", "https://verifier.env2.net/responseUri"
				)
			), Verifier(
				"https://verifier.env2.net", listOf(
					"https://verifier.env3.net/responseUri", "https://verifier.env2.net/responseUri"
				)
			)
		)
	}

	@After
	fun tearDown() {
		clearAllMocks()
	}

	@Test
	fun `should throw invalid input exception if name field is available in client_metadata but the value is empty`() {
		encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
			mapOf(
				"client_id" to "https://verifier.env1.net",
				"presentation_definition" to presentationDefinition,
				"client_metadata" to """{"client_name":""}"""
			)
		)
		val expectedExceptionMessage =
			"Invalid Input: client_metadata->client_name value cannot be empty string or null"

		actualException =
			Assert.assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
				openID4VP.authenticateVerifier(
					encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
				)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if name field is available in client_metadata but the value is null`() {
		encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
			mapOf(
				"client_id" to "https://verifier.env1.net",
				"presentation_definition" to presentationDefinition,
				"client_metadata" to """{"client_name":null}"""
			)
		)
		val expectedExceptionMessage =
			"Invalid Input: client_metadata->client_name value cannot be empty string or null"

		actualException =
			Assert.assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
				openID4VP.authenticateVerifier(
					encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
				)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if log_url field is available in client_metadata but the value is empty`() {
		encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
			mapOf(
				"client_id" to "https://verifier.env1.net",
				"presentation_definition" to presentationDefinition,
				"client_metadata" to """{"client_name":"verifier","logo_uri":""}"""
			)
		)
		val expectedExceptionMessage =
			"Invalid Input: client_metadata->logo_uri value cannot be empty string or null"

		actualException =
			Assert.assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
				openID4VP.authenticateVerifier(
					encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
				)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}
}