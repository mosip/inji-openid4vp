package io.mosip.openID4VP.jwt

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.decodeBase64Data
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.testData.clientMetadataString
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.*

class JWEHandlerJvmTest {
    private lateinit var clientMetadata: ClientMetadata
    private lateinit var jweHandler: JWEHandler
    private lateinit var publicKey: Jwk
    private val walletNonce = "wallet123"
    private val verifierNonce = "verifier456"

    @BeforeTest
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

    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should contain all the headers parameters of JWE successfully`() {
        val payload = mapOf("key1" to "value1", "key2" to 123)

        val encryptedResponse = jweHandler.generateEncryptedResponse(payload)

        assertNotNull(encryptedResponse)
        assert(encryptedResponse.isNotEmpty())
        val jweParts = encryptedResponse.split(".")
        assertTrue(jweParts.size == 5)

        val decodedJWEHeader = convertJsonToMap(String(decodeBase64Data(jweParts[0])))

        assertEquals(walletNonce, decodedJWEHeader["apu"])
        assertEquals(verifierNonce, decodedJWEHeader["apv"])
        assertEquals(publicKey.kid, decodedJWEHeader["kid"])
        assertEquals(JWEAlgorithm.ECDH_ES.name, decodedJWEHeader["alg"])
        assertEquals(EncryptionMethod.A256GCM.name, decodedJWEHeader["enc"])
        assertEquals("OKP", (decodedJWEHeader["epk"] as Map<*, *>)["kty"])
        assertEquals("X25519", (decodedJWEHeader["epk"] as Map<*, *>)["crv"])
    }

}