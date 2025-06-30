package io.mosip.openID4VP.jwt.jwe.encryption

import com.nimbusds.jose.crypto.X25519Encrypter
import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlin.test.*


class EncryptionProviderTest {


    @AfterTest
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

        assertTrue(encrypter is X25519Encrypter)
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

        val exception = assertFailsWith<OpenID4VPExceptions.UnsupportedKeyExchangeAlgorithm> {
            EncryptionProvider.getEncrypter(jwk)
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("Required Key exchange algorithm is not supported", exception.message)
    }
}
