package io.mosip.openID4VP.common

import android.util.Log
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import foundation.identity.jsonld.JsonLDObject
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class LoggerTest {
	private lateinit var expectedValue: String
	private lateinit var expectedExceptionMessage: String
	private lateinit var actualException: Exception

	@Before
	fun setUp() {
		mockkStatic(Log::class)
		every { Log.e(any(), any()) } answers {
			val tag = arg<String>(0)
			val msg = arg<String>(1)
			println("Error: logTag: $tag | Message: $msg")
			0
		}
		Logger.setTraceabilityId("test-openId4VP")
	}

	@After
	fun tearDown() {
		clearAllMocks()
	}

	@Test
	fun `should return log tag with library name and provided class name`() {
		expectedValue = "INJI-OpenID4VP : class name - LoggerTest | traceID - test-openId4VP"
		val logTag: String = Logger.getLogTag(javaClass.simpleName)

		assertEquals(expectedValue, logTag)
	}

	@Test
	fun `should return invalid_request exception if exception type input value is MissingInput`() {
		expectedExceptionMessage = "invalid_request: parent field name->current field name param is required"
		actualException = Logger.handleException(
			exceptionType = "MissingInput", fieldPath = listOf("parent field name", "current field name"), className = javaClass.simpleName
		)

		assertEquals(expectedExceptionMessage,actualException.message)
	}

	@Test
	fun `should return invalid_request exception if exception type input value is InvalidInput and field data is of type String`() {
		expectedExceptionMessage = "invalid_request: parent field name->current field name value cannot be an empty string, null, or an integer"
		actualException = Logger.handleException(
			exceptionType = "InvalidInput", fieldPath = listOf("parent field name", "current field name"), className = javaClass.simpleName, fieldType = "String"
		)

		assertEquals(expectedExceptionMessage,actualException.message)
	}

	@Test
	fun `should return invalid_request pattern exception if exception type input value is InvalidInputPattern`() {
		expectedExceptionMessage = "invalid_request: parent field name->current field name pattern is not matching with OpenId4VP specification"
		actualException = Logger.handleException(
			exceptionType = "InvalidInputPattern", fieldPath = listOf("parent field name", "current field name"), className = javaClass.simpleName
		)

		assertEquals(expectedExceptionMessage,actualException.message)
	}

	@Test
	fun name() {

		val abc= VPResponseMetadata(
			"test-id",
			"test-challenge",
			"test-state",
			"test-issuer",
		)

		val unsignedVPTokenMap = jacksonObjectMapper().writeValueAsString(abc)
		val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(unsignedVPTokenMap)

		val message = vcJsonLdObject.toJson()
		println(message)

		//println(Json.encodeToString(vcJsonLdObject))
	}
}