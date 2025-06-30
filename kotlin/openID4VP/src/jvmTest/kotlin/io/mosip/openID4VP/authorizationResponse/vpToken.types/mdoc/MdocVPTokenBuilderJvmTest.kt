package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.Array
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.mdocCredential
import kotlin.test.*
import co.nstant.`in`.cbor.model.Map as CborMap

class MdocVPTokenBuilderJvmTest {

    private lateinit var mdocVPTokenSigningResult: MdocVPTokenSigningResult
    private lateinit var mdocCredentials: List<String>
    private lateinit var deviceAuthentication: DeviceAuthentication

    @BeforeTest
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


    }
    @Test
    fun `should decode base64 using JVM decoder`() {
        val input = "aGVsbG8=" // "hello"
        val decoded = decodeBase64Data(input)
        assertEquals("hello", decoded.toString(Charsets.UTF_8))
        val result = MdocVPTokenBuilder(mdocVPTokenSigningResult, mdocCredentials).build()

        assertNotNull(result)

        val decodedResult = decodeBase64Data(result.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as Map

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
        val multipleCredentials = mdocCredentials + encodeToBase64Url(mdocCredential2)

        val result = MdocVPTokenBuilder(mdocVPTokenSigningResult, multipleCredentials).build()

        assertNotNull(result)
        val decodedResult = decodeBase64Data(result.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as CborMap

        val documents = decodedCbor[UnicodeString("documents")] as Array
        assertNotNull(documents)
        assertTrue(documents.dataItems.size == 2)
    }

    @Test
    fun `should throw exception when device authentication signature is missing`() {
        val emptyMetadata = MdocVPTokenSigningResult(docTypeToDeviceAuthentication = mapOf())

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            MdocVPTokenBuilder(emptyMetadata, mdocCredentials).build()
        }

        assertEquals(
            "Device authentication signature not found for mdoc credential docType org.iso.18013.5.1.mDL",
            exception.message
        )
    }

}