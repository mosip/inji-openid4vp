package io.mosip.openID4VP.common

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
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
		Logger.setTraceability("test-openId4VP")
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
	fun `should return missing input exception if exception type input value is MissingInput`() {
		expectedExceptionMessage = "Missing Input: parent field name : current field name param is required"
		actualException = Logger.handleException(
			"MissingInput", "parent field name", "current field name", javaClass.simpleName
		)

		assertEquals(expectedExceptionMessage,actualException.message)
	}

	@Test
	fun `should return invalid input exception if exception type input value is InvalidInput`() {
		expectedExceptionMessage = "Invalid Input: parent field name : current field name value cannot be empty or null"
		actualException = Logger.handleException(
			"InvalidInput", "parent field name", "current field name", javaClass.simpleName
		)

		assertEquals(expectedExceptionMessage,actualException.message)
	}

	@Test
	fun `should return invalid input pattern exception if exception type input value is InvalidInputPattern`() {
		expectedExceptionMessage = "Invalid Input Pattern: parent field name : current field name pattern is not matching with OpenId4VP specification"
		actualException = Logger.handleException(
			"InvalidInputPattern", "parent field name", "current field name", javaClass.simpleName
		)

		assertEquals(expectedExceptionMessage,actualException.message)
	}
}