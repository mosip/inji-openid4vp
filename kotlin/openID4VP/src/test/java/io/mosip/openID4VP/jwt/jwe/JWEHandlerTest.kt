
package io.mosip.openID4VP.jwt.jwe

import android.util.Log
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.just
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.slot
import io.mockk.spyk
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.jwt.jwe.encryption.EncryptionProvider
import io.mosip.openID4VP.testData.clientMetadataString
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue

class JWEHandlerTest {

    private lateinit var clientMetadata: ClientMetadata
    private lateinit var jweHandler: JWEHandler
    private lateinit var publicKey: Jwk
    private val walletNonce = "wallet123"
    private val verifierNonce = "verifier456"

    @Before
    fun setUp() {
        clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        publicKey = clientMetadata.jwks!!.keys[0]
        jweHandler = JWEHandler(
            clientMetadata.authorizationEncryptedResponseAlg!!,
            clientMetadata.authorizationEncryptedResponseEnc!!,
            publicKey,
            walletNonce,
            verifierNonce
        )

        mockkObject(Logger)
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
    fun `should generate encrypted response successfully`() {
        val payload = mapOf("key1" to "value1", "key2" to 123)

        val encryptedResponse = jweHandler.generateEncryptedResponse(payload)

        assertNotNull(encryptedResponse)
        assert(encryptedResponse.isNotEmpty())
        assertTrue(encryptedResponse.split(".").size == 5)
    }

    @Test
    fun `should contain all the headers parameters of JWE successfully`() {
        val payload = mapOf("key1" to "value1", "key2" to 123)

        val encryptedResponse = jweHandler.generateEncryptedResponse(payload)

        assertNotNull(encryptedResponse)
        assert(encryptedResponse.isNotEmpty())
        val jweParts = encryptedResponse.split(".")
        assertTrue(jweParts.size == 5)

        val decodedJWEHeader = convertJsonToMap(String(Decoder.decodeBase64Data(jweParts[0])))

        assertEquals(walletNonce, decodedJWEHeader["apu"])
        assertEquals(verifierNonce, decodedJWEHeader["apv"])
        assertEquals(publicKey.kid, decodedJWEHeader["kid"])
        assertEquals(JWEAlgorithm.ECDH_ES.name, decodedJWEHeader["alg"])
        assertEquals(EncryptionMethod.A256GCM.name, decodedJWEHeader["enc"])
        assertEquals("OKP", (decodedJWEHeader["epk"] as Map<*, *>)["kty"])
        assertEquals("X25519", (decodedJWEHeader["epk"] as Map<*, *>)["crv"])
    }

    @Test
    fun `should throw exception when encryption fails`() {
        val payload = mapOf("key1" to "value1")

        mockkObject(EncryptionProvider)
        every { EncryptionProvider.getEncrypter(any()) } throws OpenID4VPExceptions.JweEncryptionFailure("JWEHandler.kt")

        val exception = assertThrows(OpenID4VPExceptions::class.java) {
            jweHandler.generateEncryptedResponse(payload)
        }

        assertTrue(exception.message?.contains("Encryption failed") ?: false)


    }

    @Test
    fun `should throw exception when JWT encryption fails`() {
        val payload = mapOf("key1" to "value1")

        mockkConstructor(EncryptedJWT::class)
        every { anyConstructed<EncryptedJWT>().encrypt(any()) } throws Exception("JWT encryption failed")

        val exception = assertThrows(OpenID4VPExceptions::class.java) {
            jweHandler.generateEncryptedResponse(payload)
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("JWE Encryption failed", exception.message)

        verify {
            anyConstructed<EncryptedJWT>().encrypt(any())
        }
    }


}


