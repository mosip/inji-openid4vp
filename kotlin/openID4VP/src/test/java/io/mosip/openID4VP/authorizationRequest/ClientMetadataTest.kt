package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.testData.clientMetadata
import io.mosip.openID4VP.testData.createEncodedAuthorizationRequest
import io.mosip.openID4VP.testData.presentationDefinition
import io.mosip.openID4VP.testData.requestUri
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
	private val requestParams: Map<String, String> = mapOf(
		"client_id" to "https://mock-verifier.com",
		"client_id_scheme" to "redirect_uri",
		"redirect_uri" to "https://mock-verifier.com",
		"response_uri" to "https://mock-verifier.com",
		"request_uri" to requestUri,
		"request_uri_method" to "get",
		"presentation_definition" to presentationDefinition,
		"response_type" to "vp_token",
		"response_mode" to "direct_post",
		"nonce" to "VbRRB/LTxLiXmVNZuyMO8A==",
		"state" to "+mRQe1d6pBoJqF6Ab28klg==",
		"client_metadata" to clientMetadata
	)

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
			"client_id" to "https://verifier.env1.net",
			"client_id_scheme" to "pre-registered",
			"response_uri" to "https://verifier.env1.net/responseUri"
		)
		val encodedAuthorizationRequest =
			createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)
		assertDoesNotThrow {
			 openID4VP.authenticateVerifier(
				 encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
			)
		}
	}

	@Test
	fun `should throw invalid input exception if vp_formats field is not available`() {
		val authorizationRequestParamsMap = requestParams + mapOf(
			"client_id" to "https://verifier.env1.net",
			"client_id_scheme" to "pre-registered",
			"response_uri" to "https://verifier.env1.net/responseUri",
			"client_metadata" to "{\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\"}"
		)
		val encodedAuthorizationRequest =
			createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)


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
			"client_id" to "https://verifier.env1.net",
			"client_id_scheme" to "pre-registered",
			"client_metadata" to "{\"client_name\":\"\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"
		)
		val encodedAuthorizationRequest =
			createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

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
			"client_id" to "https://verifier.env1.net",
			"client_id_scheme" to "pre-registered",
			"response_uri" to "https://verifier.env1.net/responseUri",
			"client_metadata" to "{\"client_name\":null,\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"
		)
		val encodedAuthorizationRequest =
			createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

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
			"client_id" to "https://verifier.env1.net",
			"client_id_scheme" to "pre-registered",
			"client_metadata" to "{\"client_name\":\"verifier\",\"logo_uri\":\"\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"

		)
		val encodedAuthorizationRequest =
			createEncodedAuthorizationRequest(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

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