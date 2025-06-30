package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc

import android.util.Log
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Encoder
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.mdocCredential
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import co.nstant.`in`.cbor.model.Map as CborMap

class MdocVPTokenBuilderTest {

    private lateinit var mdocVPTokenSigningResult: MdocVPTokenSigningResult
    private lateinit var mdocCredentials: List<String>
    private lateinit var deviceAuthentication: DeviceAuthentication

    @Before
    fun setup() {
        deviceAuthentication = DeviceAuthentication(
            signature = "c2lnbmF0dXJlX2RhdGE=",
            algorithm = "ES256"
        )
        mdocVPTokenSigningResult = MdocVPTokenSigningResult(
            docTypeToDeviceAuthentication = mapOf(
                "org.iso.18013.5.1.mDL" to deviceAuthentication
            )
        )
        mdocCredentials = listOf(mdocCredential)

        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
        every { Log.d(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
    }

    @Test
    fun `should return valid MdocVPToken with expected structure`() {
        val result = MdocVPTokenBuilder(mdocVPTokenSigningResult, mdocCredentials).build()

        assertNotNull(result)
        val decodedResult = Decoder.decodeBase64Data(result.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as CborMap

        assertEquals("1.0", decodedCbor[UnicodeString("version")].toString())
        assertEquals(0, decodedCbor[UnicodeString("status")].toString().toInt())
        assertNotNull(decodedCbor[UnicodeString("documents")])
    }

    @Test
    fun `should return token with multiple documents for multiple credentials`() {
        val mdocCredential2 = encodeCbor(
            cborMapOf(
                "docType" to "org.iso.18013.5.1.elc",
                "issuerSigned" to cborMapOf()
            )
        )
        mdocVPTokenSigningResult = MdocVPTokenSigningResult(
            docTypeToDeviceAuthentication = mapOf(
                "org.iso.18013.5.1.mDL" to deviceAuthentication,
                "org.iso.18013.5.1.elc" to deviceAuthentication
            )
        )
        val multipleCredentials = mdocCredentials + Encoder.encodeToBase64Url(mdocCredential2)

        val result = MdocVPTokenBuilder(mdocVPTokenSigningResult, multipleCredentials).build()

        assertNotNull(result)
        val decodedResult = Decoder.decodeBase64Data(result.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as CborMap

        val documents = decodedCbor[UnicodeString("documents")] as Array
        assertNotNull(documents)
        assertTrue(documents.dataItems.size == 2)
    }

    @Test
    fun `should throw exception when device authentication signature is missing`() {
        val emptyMetadata = MdocVPTokenSigningResult(docTypeToDeviceAuthentication = mapOf())

        val exception = assertThrows(OpenID4VPExceptions.MissingInput::class.java) {
            MdocVPTokenBuilder(emptyMetadata, mdocCredentials).build()
        }

        assertEquals(
            "Device authentication signature not found for mdoc credential docType org.iso.18013.5.1.mDL",
            exception.message
        )
    }


}