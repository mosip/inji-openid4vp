package io.mosip.openID4VP.common

import android.util.Base64.encodeToString
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
import org.bouncycastle.util.encoders.Base64
import java.math.BigInteger
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals


class EncoderTest {

    @BeforeTest
    fun setUp() {
        mockkStatic(Base64::class)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should encode the content to base64 url successfully with API lesser than Version O`() {
        every {
            encodeToString(
                "hello world".toByteArray(),
                any()
            )
        } returns "aGVsbG8gd29ybGQ="

        val encodedData = encodeToBase64Url("hello world".toByteArray())

        assertEquals("aGVsbG8gd29ybGQ=", encodedData)
    }

    @Test
    fun name() {
            // 1. Generate the Ed25519 key pair
            val jwk: OctetKeyPair = OctetKeyPairGenerator(Curve.Ed25519)
                .keyIDFromThumbprint(true)
                .generate()

            println(":::::jwk"+jwk.toString())
            // 2. Decode the public key (base64url) into raw bytes
            val rawPubKey = jwk.x.decode() // 32 bytes


            val rawPrivateKey = jwk.d // 32 bytes

            print(":::::private key: $rawPrivateKey")


            // 3. Prepend multicodec prefix for Ed25519 (0xED 0x01)
            val ed25519Prefix = byteArrayOf(0xED.toByte(), 0x01.toByte())
            val prefixedPubKey = ed25519Prefix + rawPubKey

            // 4. Encode to base58btc using multibase
            val multibasePubKey = Multibase.encode(Multibase.Base.Base58BTC, prefixedPubKey)

            println("z6M-form multibase key: $multibasePubKey")
            //return multibasePubKey

    }
}
