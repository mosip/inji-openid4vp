package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.Array
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.mdocCredential
import kotlin.test.*
import co.nstant.`in`.cbor.model.Map as CborMap

class MdocVPTokenBuilderJvmTest {

    private lateinit var mdocVPTokenSigningResult: MdocVPTokenSigningResult
    private lateinit var mdocCredentials: List<String>
    private lateinit var deviceAuthentication: DeviceAuthentication

    private val docType = "org.iso.18013.5.1.mDL"

    @BeforeTest
    fun setup() {
        deviceAuthentication = DeviceAuthentication(
            signature = "c2lnbmF0dXJlX2RhdGE=",
            algorithm = "ES256"
        )
        mdocVPTokenSigningResult = MdocVPTokenSigningResult(
            docTypeToDeviceAuthentication = mapOf(
                docType to deviceAuthentication
            )
        )
        mdocCredentials = listOf(mdocCredential)
    }

    @Test
    fun `should decode base64 using JVM decoder`() {
        val input = "aGVsbG8=" // "hello"
        val decoded = decodeFromBase64Url(input)
        assertEquals("hello", decoded.toString(Charsets.UTF_8))
        val (vpTokens, descriptorMaps, nextIndex) = MdocVPTokenBuilder().build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    mdocCredential,
                    "org.iso.18013.5.1.mDL"
                )
            ),
            unsignedVPTokenResult = Pair(
                null, UnsignedMdocVPToken(mapOf(docType to "deviceAuthentication"))
            ),
            vpTokenSigningResult = mdocVPTokenSigningResult,
            rootIndex = 0
        )

        val vpToken = mdocVPToken(vpTokens)

        val decodedResult = decodeFromBase64Url(vpToken.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as Map

        assertEquals("1.0", decodedCbor[UnicodeString("version")].toString())
        assertEquals(0, decodedCbor[UnicodeString("status")].toString().toInt())
        assertNotNull(decodedCbor[UnicodeString("documents")])
        assertEquals(1, descriptorMaps.size)
        assertEquals("[DescriptorMap(id=org.iso.18013.5.1.mDL, format=mso_mdoc, path=\$[0], pathNested=null)]", descriptorMaps.toString())
        assertEquals(1, nextIndex)
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

        val (vpTokens, descriptorMaps, nextIndex) = MdocVPTokenBuilder().build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    mdocCredentials[0],
                    "org.iso.18013.5.1.mDL"
                ),
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    encodeToBase64Url(mdocCredential2),
                    "org.iso.18013.5.1.elc"
                )
            ),
            unsignedVPTokenResult = Pair(
                null, UnsignedMdocVPToken(
                    mapOf(
                        "org.iso.18013.5.1.mDL" to "deviceAuthentication1",
                        "org.iso.18013.5.1.elc" to "deviceAuthentication2"
                    )
                )
            ),
            vpTokenSigningResult = mdocVPTokenSigningResult,
            rootIndex = 0
        )

        val vpToken = mdocVPToken(vpTokens)
        val decodedResult = decodeFromBase64Url(vpToken.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as CborMap

        val documents = decodedCbor[UnicodeString("documents")] as Array
        assertNotNull(documents)
        assertTrue(documents.dataItems.size == 2)

        assertEquals( 1, nextIndex)
        assertEquals("[DescriptorMap(id=org.iso.18013.5.1.mDL, format=mso_mdoc, path=\$[0], pathNested=null), DescriptorMap(id=org.iso.18013.5.1.elc, format=mso_mdoc, path=\$[0], pathNested=null)]", descriptorMaps.toString())
    }

    @Test
    fun `should throw exception when device authentication signature is missing`() {
        val emptyMetadata = MdocVPTokenSigningResult(docTypeToDeviceAuthentication = mapOf())

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            MdocVPTokenBuilder().build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(
                        FormatType.MSO_MDOC,
                        mdocCredentials[0],
                        "org.iso.18013.5.1.mDL"
                    )
                ),
                unsignedVPTokenResult = Pair(
                    null, UnsignedMdocVPToken(
                        mapOf(
                            "org.iso.18013.5.1.mDL" to "deviceAuthentication1"
                        )
                    )
                ),
                vpTokenSigningResult = emptyMetadata,
                rootIndex = 0
            )
        }

        assertEquals(
            "Device authentication signature not found for mdoc credential docType org.iso.18013.5.1.mDL",
            exception.message
        )
    }

    private fun mdocVPToken(vpTokens: List<MdocVPToken>): MdocVPToken {
        assertNotNull(vpTokens)
        assertTrue(vpTokens.size == 1)
        val vpToken = vpTokens.first() as MdocVPToken
        return vpToken
    }
}