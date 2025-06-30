package io.mosip.openID4VP.jwt.jwe.encryption

import android.util.Log
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.crypto.X25519Encrypter
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jwe.encryption.EncryptionProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class EncryptionProviderTest {
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
    fun `getEncrypter should create X25519Encrypter for OKP key type`() {
        val jwk = Jwk(
            alg = "ECDH-ES",
            kty = "OKP",
            use = "enc",
            crv = "X25519",
            x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
            kid = "ed-key1"
        )
        val encrypter = EncryptionProvider.getEncrypter(jwk)

        assert(encrypter is X25519Encrypter)
    }

    @Test
    fun `getEncrypter should throw UnsupportedKeyExchangeAlgorithm for non-OKP key type`() {
        val jwk = Jwk(
            alg = "ECDH-ES",
            kty = "UNSUPPORTED",
            use = "enc",
            crv = "X25519",
            x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
            kid = "ed-key1"
        )

        val exception = assertThrows(OpenID4VPExceptions.UnsupportedKeyExchangeAlgorithm::class.java) {
            EncryptionProvider.getEncrypter(jwk)
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("Required Key exchange algorithm is not supported", exception.message)
    }

}

