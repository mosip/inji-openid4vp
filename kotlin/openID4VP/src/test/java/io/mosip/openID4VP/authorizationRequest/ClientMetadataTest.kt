package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.testData.createUrlEncodedData
import io.mosip.openID4VP.testData.requestParams
import io.mosip.openID4VP.testData.trustedVerifiers
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertDoesNotThrow

class ClientMetadataTest {
	private lateinit var actualException: Exception
	private lateinit var openID4VP: OpenID4VP
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
	}

	@After
	fun tearDown() {
		clearAllMocks()
	}

	@Test
	fun `should parse client metadata successfully`() {
		val authorizationRequestParamsMap = requestParams + mapOf(
			CLIENT_ID.value to "https://verifier.env1.net",
			CLIENT_ID_SCHEME.value to "pre-registered",
			RESPONSE_URI.value to "https://verifier.env1.net/responseUri"
		)
		val encodedAuthorizationRequest =
			createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)
		assertDoesNotThrow {
			 openID4VP.authenticateVerifier(
				 encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
			)
		}
	}

	@Test
	fun `should throw invalid input exception if vp_formats field is not available`() {
		val authorizationRequestParamsMap = requestParams + mapOf(
			CLIENT_ID.value to "https://verifier.env1.net",
			CLIENT_ID_SCHEME.value to "pre-registered",
			RESPONSE_URI.value to "https://verifier.env1.net/responseUri",
			CLIENT_METADATA.value to "{\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\"}"
		)
		val encodedAuthorizationRequest =
			createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)


		val expectedExceptionMessage =
			"Invalid Input: client_metadata->vp_formats value cannot be empty or null"

		actualException =
			Assert.assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
				openID4VP.authenticateVerifier(
					encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
				)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if name field is available in client_metadata but the value is empty`() {
		val authorizationRequestParamsMap = requestParams + mapOf(
			CLIENT_ID.value to "https://verifier.env1.net",
			CLIENT_ID_SCHEME.value to "pre-registered",
			CLIENT_METADATA.value to "{\"client_name\":\"\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"
		)
		val encodedAuthorizationRequest =
			createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

		val expectedExceptionMessage =
			"Invalid Input: client_metadata->client_name value cannot be an empty string, null, or an integer"

		actualException =
			Assert.assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
				openID4VP.authenticateVerifier(
					encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
				)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if name field is available in client_metadata but the value is null`() {
		val authorizationRequestParamsMap = requestParams + mapOf(
			CLIENT_ID.value to "https://verifier.env1.net",
			CLIENT_ID_SCHEME.value to "pre-registered",
			RESPONSE_URI.value to "https://verifier.env1.net/responseUri",
			CLIENT_METADATA.value to "{\"client_name\":null,\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"
		)
		val encodedAuthorizationRequest =
			createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

		val expectedExceptionMessage =
			"Invalid Input: client_metadata->client_name value cannot be an empty string, null, or an integer"

		actualException =
			Assert.assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
				openID4VP.authenticateVerifier(
					encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
				)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if log_url field is available in client_metadata but the value is empty`() {
		val authorizationRequestParamsMap = requestParams + mapOf(
			CLIENT_ID.value to "https://verifier.env1.net",
			CLIENT_ID_SCHEME.value to "pre-registered",
			CLIENT_METADATA.value to "{\"client_name\":\"\",\"client_name\":\"verifier\",\"logo_uri\":\"\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"

		)
		val encodedAuthorizationRequest =
			createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

		val expectedExceptionMessage =
			"Invalid Input: client_metadata->logo_uri value cannot be an empty string, null, or an integer"

		actualException =
			Assert.assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
				openID4VP.authenticateVerifier(
					encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
				)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}
}