package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.sdJwt.SdJwtVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.sdJwt.SdJwtVPTokenSigningResult
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SdJwtVPTokenBuilderJvmTest {

    private val uuid = "uuid-123"
    private val sampleSdJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6ZXhhbXBsZToxMjMifQ.signature~disclosure1~disclosure2"
    private val unsignedKBJwt = "eyJhbGciOiJFUzI1NksifQ.eyJub25jZSI6Im5vbmNlIn0"
    private val kbJwtSignature = "dummy_signature"

    @Test
    fun `should build final SD-JWT VP Token successfully`() {
        val builder = SdJwtVPTokenBuilder(
            VPTokenSigningResult = SdJwtVPTokenSigningResult(
                uuidToKbJWTSignature = mutableMapOf(uuid to kbJwtSignature)
            ),
            credentials = mutableMapOf(uuid to sampleSdJwt),
            unsignedKBJwts = UnsignedSdJwtVPToken(
                uuidToUnsignedKBT = mutableMapOf(uuid to unsignedKBJwt)
            ),
            uuid = uuid
        )

        val result = builder.build()
        val expected = "$sampleSdJwt$unsignedKBJwt.$kbJwtSignature"
        assertEquals(expected, result.value)
    }

    @Test
    fun `should throw MissingInput when SD-JWT credential is missing`() {
        val builder = SdJwtVPTokenBuilder(
            VPTokenSigningResult = SdJwtVPTokenSigningResult(
                uuidToKbJWTSignature = mutableMapOf(uuid to kbJwtSignature)
            ),
            credentials = mutableMapOf("121" to sampleSdJwt),
            unsignedKBJwts = UnsignedSdJwtVPToken(
                uuidToUnsignedKBT = mutableMapOf(uuid to unsignedKBJwt)
            ),
            uuid = uuid
        )

        val exception = assertThrows(OpenID4VPExceptions.MissingInput::class.java) {
            builder.build()
        }

        assertEquals(
            "Missing SD-JWT credential for uuid: $uuid",
            exception.message
        )
    }

    @Test
    fun `should throw MissingInput when KB-JWT signature is missing`() {
        val builder = SdJwtVPTokenBuilder(
            VPTokenSigningResult = SdJwtVPTokenSigningResult(
                uuidToKbJWTSignature = mutableMapOf("121" to kbJwtSignature)
            ),
            credentials = mutableMapOf(uuid to sampleSdJwt),
            unsignedKBJwts = UnsignedSdJwtVPToken(
                uuidToUnsignedKBT = mutableMapOf(uuid to unsignedKBJwt)
            ),
            uuid = uuid
        )

        val exception = assertThrows(OpenID4VPExceptions.MissingInput::class.java) {
            builder.build()
        }

        assertEquals(
            "Missing Key Binding JWT signature for uuid: $uuid",
            exception.message
        )
    }

    @Test
    fun `should succeed without holder binding when both KB-JWT and signature are absent`() {
        val builder = SdJwtVPTokenBuilder(
            VPTokenSigningResult = SdJwtVPTokenSigningResult(
                uuidToKbJWTSignature = mutableMapOf() // signature absent
            ),
            credentials = mutableMapOf(uuid to sampleSdJwt),
            unsignedKBJwts = UnsignedSdJwtVPToken(
                uuidToUnsignedKBT = mutableMapOf() // unsigned KB absent
            ),
            uuid = uuid
        )

        val result = builder.build()

        assertEquals(sampleSdJwt, result.value)
    }


    @Test
    fun `should throw InvalidData when signature is present but KB-JWT is missing`() {
        val builder = SdJwtVPTokenBuilder(
            VPTokenSigningResult = SdJwtVPTokenSigningResult(
                uuidToKbJWTSignature = mutableMapOf(uuid to kbJwtSignature, "123" to "signature") // signature present
            ),
            credentials = mutableMapOf(uuid to sampleSdJwt),
            unsignedKBJwts = UnsignedSdJwtVPToken(
                uuidToUnsignedKBT = mutableMapOf("123" to unsignedKBJwt) // unsigned KB missing
            ),
            uuid = uuid
        )

        val exception = assertThrows(OpenID4VPExceptions.InvalidData::class.java) {
            builder.build()
        }

        assertEquals(
            "Signature present but unsigned KB-JWT missing for uuid: $uuid",
            exception.message
        )
    }


}
