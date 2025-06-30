package io.mosip.openID4VP.common

import android.util.Log
import co.nstant.`in`.cbor.model.*
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.Map
import io.mockk.*
import io.mosip.openID4VP.testData.mdocCredential
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertThrows
import java.lang.IllegalArgumentException

class CborUtilsTest {

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
    fun `should tag data with tag 24`() {
        val testString = UnicodeString("test")
        val result = tagEncodedCbor(testString)

        assertEquals(24, result.tag.value)
        assertTrue(result is ByteString)
    }

    @Test
    fun `encodeCbor and decodeCbor should be inverse operations`() {
        val testString = UnicodeString("test")
        val encoded = encodeCbor(testString)
        val decoded = decodeCbor(encoded)

        assertEquals(testString.toString(), decoded.toString())
    }

    @Test
    fun ` should create cbor array with different types of data`() {
        val result = cborArrayOf(
            "string",
            123,
            123L,
            1.23,
            "hello".toByteArray(),
            UnicodeString("unicode"),
            null
        )

        assertTrue(result is Array)
        val array = result as Array
        assertEquals(7, array.dataItems.size)
        assertEquals("string", array.dataItems[0].toString())
        assertEquals("123", array.dataItems[1].toString())
        assertEquals("123", array.dataItems[2].toString())
        assertEquals("1.23", array.dataItems[3].toString())
        assertTrue(array.dataItems[4] is ByteString)
        assertEquals("unicode", array.dataItems[5].toString())
        assertNull(array.dataItems[6])
    }

    @Test
    fun `cborArrayOf should throw exception for unsupported type`() {
        val exception = assertThrows(IllegalArgumentException::class.java){
            cborArrayOf(Object())
        }
        assertTrue(exception.message!!.contains("Unsupported type"))

    }

    @Test
    fun ` should create cbor map with different types`() {
        val map = cborMapOf(
            "key1" to "value1",
            123 to 456,
            "key3" to 789L,
            "key4" to 1.23,
            "key5" to "hello".toByteArray(),
            "key6" to UnicodeString("unicode"),
            "key7" to null
        )

        assertTrue(map is Map)
        val cborMap = map as Map
        assertEquals(7, cborMap.keys.size)

        val key1 = UnicodeString("key1")
        assertEquals("value1", cborMap.get(key1).toString())

        val key2 = UnsignedInteger(123)
        assertEquals("456", cborMap.get(key2).toString())

        val key7 = UnicodeString("key7")
        assertNull(cborMap.get(key7))
    }

    @Test
    fun `cborMapOf should throw exception for null key`() {
        val exception = assertThrows(IllegalArgumentException::class.java){
            cborMapOf(null to "value")
        }
        println(exception)
        assertEquals(exception.message, "Key cannot be null")
    }

    @Test
    fun `cborMapOf should throw exception for unsupported key type`() {
        val exception = assertThrows(IllegalArgumentException::class.java){
            cborMapOf(Object() to "value")
        }
        assertTrue(exception.message!!.contains("Unsupported key type"))
    }

    @Test
    fun `cborMapOf should throw exception for unsupported value type`() {
        val exception = assertThrows(IllegalArgumentException::class.java){
            cborMapOf("key" to Object())
        }
        assertTrue(exception.message!!.contains("Unsupported value type"))
    }

    @Test
    fun `createHashedDataItem should create ByteString`() {
        val result = createHashedDataItem("test", 123)
        assertTrue(result is ByteString)
        assertEquals(32, result.bytes.size)
    }

    @Test
    fun `generateHash should produce consistent hashes`() {
        val input = UnicodeString("test")
        val hash1 = generateHash(input)
        val hash2 = generateHash(input)

        assertTrue(hash1.contentEquals(hash2))
        assertEquals(32, hash1.size)
    }

    @Test
    fun `getMdocDocType should extract docType from credential`() {
        val result = getDecodedMdocCredential(mdocCredential)
        assertTrue(result is Map)
    }

    @Test
    fun `mapSigningAlgorithmToProtectedAlg should return correct value for supported algorithm`() {
        assertEquals(-7L, mapSigningAlgorithmToProtectedAlg("ES256"))
        assertEquals(-35L, mapSigningAlgorithmToProtectedAlg("ES384"))
        assertEquals(-36L, mapSigningAlgorithmToProtectedAlg("ES512"))
        assertEquals(-8L, mapSigningAlgorithmToProtectedAlg("EdDSA"))
        assertEquals(-37L, mapSigningAlgorithmToProtectedAlg("PS256"))
        assertEquals(-38L, mapSigningAlgorithmToProtectedAlg("PS384"))
        assertEquals(-39L, mapSigningAlgorithmToProtectedAlg("PS512"))
    }

    @Test
    fun `mapSigningAlgorithmToProtectedAlg should throw exception for unsupported algorithm`() {
        val exception = assertThrows(IllegalArgumentException::class.java) {
            mapSigningAlgorithmToProtectedAlg("UNSUPPORTED")
        }
        assertTrue(exception.message!!.contains("Unsupported signing algorithm: UNSUPPORTED"))
    }
}