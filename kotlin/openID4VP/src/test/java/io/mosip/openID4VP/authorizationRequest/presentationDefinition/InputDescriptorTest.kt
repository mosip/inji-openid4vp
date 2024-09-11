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

class InputDescriptorTest {
    private lateinit var presentationDefinition: String
    private lateinit var expectedExceptionMessage: String

    @Before
    fun setUp(){
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
    }

    @After
    fun tearDown(){
        clearAllMocks()
    }

    @Test
    fun `should throw missing input exception if id param is missing`(){
        presentationDefinition =
            "{\"id\":\"id_123\",\"input_descriptors\":[{\"constraints\":{\"fields\":[{\"path\":[\"\$.type\"]}]}}]}"
        expectedExceptionMessage = "Missing Input: input_descriptor : id param is required"

        val actualException =
            Assert.assertThrows(AuthorizationRequestExceptions.MissingInput::class.java) {
                validatePresentationDefinition(presentationDefinition)
            }

        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw missing input exception if constraints param is missing`(){
        presentationDefinition =
            "{\"input_descriptors\":[{\"id\":\"id_123\"}]}"
        expectedExceptionMessage = "Missing Input: input_descriptor : constraints param is required"

        val actualException =
            Assert.assertThrows(AuthorizationRequestExceptions.MissingInput::class.java) {
                validatePresentationDefinition(presentationDefinition)
            }

        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if id param value is empty`(){
        presentationDefinition =
            "{\"id\":\"pd_123\",\"input_descriptors\":[{\"id\":\"\",\"constraints\":{\"fields\":[{\"path\":[\"\$.type\"]}]}}]}"
        expectedExceptionMessage = "Invalid Input: input_descriptor : id value cannot be empty or null"

        val actualException =
            Assert.assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                validatePresentationDefinition(presentationDefinition)
            }

        Assert.assertEquals(expectedExceptionMessage, actualException.message)
    }
}