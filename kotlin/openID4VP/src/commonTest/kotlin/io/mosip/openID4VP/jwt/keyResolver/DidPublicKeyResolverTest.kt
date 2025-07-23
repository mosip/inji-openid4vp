package io.mosip.openID4VP.jwt.keyResolver

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.util.Base64URL
import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkConstructor
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.HEADER
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.PAYLOAD
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.SIGNATURE
import io.mosip.openID4VP.jwt.keyResolver.types.DidPublicKeyResolver
import io.mosip.vercred.vcverifier.DidWebResolver
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.DidResolutionFailed
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.Hex
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import kotlin.test.*

class DidPublicKeyResolverTest {

    private lateinit var resolver: DidPublicKeyResolver

    @BeforeTest
    fun setUp() {
        val mockDidUrl = "did:web:example:123456789#keys-1"
        mockkConstructor(DidWebResolver::class)
        resolver = DidPublicKeyResolver(mockDidUrl)


    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should return public key when kid matches`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf(
                    "id" to "did:web:example:123456789#keys-1",
                    "publicKeyMultibase" to "mockPublicKey123"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:example:123456789#keys-1")
        val result = resolver.resolveKey(header)

        assertEquals("mockPublicKey123", result)
    }

    @Test
    fun `should throw exception when kid is missing`() {
        every { anyConstructed<DidWebResolver>().resolve() } returns mapOf("didDocument" to "mockResponse")

        val exception = assertFailsWith<KidExtractionFailed> {
            resolver.resolveKey(emptyMap())
        }
        assertEquals("KID extraction from DID document failed", exception.message)
    }

    @Test
    fun `should throw exception when did resolution fails`() {
        every { anyConstructed<DidWebResolver>().resolve() } throws DidResolutionFailed("Did document could not be fetched")

        val exception = assertFailsWith<PublicKeyResolutionFailed> {
            resolver.resolveKey(emptyMap())
        }
        assertEquals("Did document could not be fetched", exception.message)
    }

    @Test
    fun `should throw exception when public key extraction fails`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("id" to "did:web:example:123456789#keys-1") // No "publicKey"
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:example:123456789#keys-1")

        val exception = assertFailsWith<PublicKeyExtractionFailed> {
            resolver.resolveKey(header)
        }
        assertEquals("Public key extraction failed for kid: did:example:123456789#keys-1", exception.message)
    }

    @Test
    fun `should throw exception when publicKeyMultibase is empty  verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyMultibase" to  "",
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<InvalidData> {
            resolver.resolveKey(header)
        }
        assertEquals("publicKeyMultibase cannot be null or empty", exception.message)
    }

    @Test
    fun `should throw exception when publicKeyMultibase is null  verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyMultibase" to  null,
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<InvalidData> {
            resolver.resolveKey(header)
        }
        assertEquals("publicKeyMultibase cannot be null or empty", exception.message)
    }

    @Test
    fun `should throw exception when unsupported public key- publicKeyHex present in verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyHex" to  "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo",
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<UnsupportedPublicKeyType> {
            resolver.resolveKey(header)
        }
        assertEquals("Unsupported Public Key type. Supported: publicKeyMultibase", exception.message)
    }

    @Test
    fun `should throw exception when unsupported public key- publicKeyJwk present in verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyJwk" to  "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo",
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<UnsupportedPublicKeyType> {
            resolver.resolveKey(header)
        }
        assertEquals("Unsupported Public Key type. Supported: publicKeyMultibase", exception.message)
    }

    @Test
    fun `should throw exception when unsupported public key- publicKeyPem present in verificationMethod`() {
        val mockResponse = mapOf(
            "verificationMethod" to listOf(
                mapOf("publicKeyPem" to  "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo",
                    "controller" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                    "id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
                    "type" to "Ed25519VerificationKey2020",
                    "@context" to "https://w3id.org/security/suites/ed25519-2020/v1"
                )
            )
        )

        every { anyConstructed<DidWebResolver>().resolve() } returns mockResponse

        val header = mapOf("kid" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0")

        val exception = assertFailsWith<UnsupportedPublicKeyType> {
            resolver.resolveKey(header)
        }
        assertEquals("Unsupported Public Key type. Supported: publicKeyMultibase", exception.message)
    }

    @Test
    fun name() {


       // val header1 = mapOf("kid" to "did:web:balachandarg-tw.github.io:inji-mock-services:openid4vp-service:local#key-0")
        //val resolveKey = DidPublicKeyResolver("did:web:balachandarg-tw.github.io:inji-mock-services:openid4vp-service:local")
//
//
//        println(resolveKey)

        val jws = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmJhbGFjaGFuZGFyZy10dy5naXRodWIuaW86aW5qaS1tb2NrLXNlcnZpY2VzOm9wZW5pZDR2cC1zZXJ2aWNlOmxvY2FsI2tleS0wIn0.eyJjbGllbnRfaWQiOiJkaWQ6d2ViOmJhbGFjaGFuZGFyZy10dy5naXRodWIuaW86aW5qaS1tb2NrLXNlcnZpY2VzOm9wZW5pZDR2cC1zZXJ2aWNlOmxvY2FsIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb25fdXJpIjoiaHR0cHM6Ly8wZTA1ZTA0YTAzNjYubmdyb2stZnJlZS5hcHAvdmVyaWZpZXIvcHJlc2VudGF0aW9uX2RlZmluaXRpb25fdXJpIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Iiwibm9uY2UiOiIrTVhNRjZkcHdvQ1JHVjJrb2VnVU5nPT0iLCJzdGF0ZSI6India05tdHhGbnRMZE1kR1FWTUJydWc9PSIsInJlc3BvbnNlX3VyaSI6Imh0dHBzOi8vMGUwNWUwNGEwMzY2Lm5ncm9rLWZyZWUuYXBwL3ZlcmlmaWVyL3ZwLXJlc3BvbnNlIiwiY2xpZW50X21ldGFkYXRhIjoie1wiY2xpZW50X25hbWVcIjpcIlJlcXVlc3RlciBuYW1lXCIsXCJsb2dvX3VyaVwiOlwiPGxvZ29fdXJpPlwiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnXCI6XCJFQ0RILUVTXCIsXCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmNcIjpcIkEyNTZHQ01cIixcImp3a3NcIjp7XCJrZXlzXCI6W3tcImt0eVwiOlwiT0tQXCIsXCJjcnZcIjpcIlgyNTUxOVwiLFwidXNlXCI6XCJlbmNcIixcInhcIjpcIkJWTlZkcW9ycHhDQ25UT2trdzhTMk5BWVh2ZkV2a0MtOFJET2JockFVQTRcIixcImFsZ1wiOlwiRUNESC1FU1wiLFwia2lkXCI6XCJ2ZXJpZmllci1rZXktaWRcIn1dfSxcInZwX2Zvcm1hdHNcIjp7XCJtc29fbWRvY1wiOntcImFsZ1wiOltcIkVTMjU2XCJdfSxcImxkcF92cFwiOntcInByb29mX3R5cGVcIjpbXCJFZDI1NTE5U2lnbmF0dXJlMjAxOFwiLFwiRWQyNTUxOVNpZ25hdHVyZTIwMjBcIixcIlJzYVNpZ25hdHVyZTIwMThcIl19fX0ifQ.M3OeSA1chevXFuOnfWHazIbnWy9rkOUZEBy7p82934j0TMbDBo_mUdw0wC_4gA5zt64GBLORUHzi1lGbfTYMBA"
//
        val parts = jws.split(".")
        val header = parts[HEADER.number]
        val payload = parts[PAYLOAD.number]
        val signature = decodeFromBase64Url(parts[SIGNATURE.number])
//
//
//
//        val publicKey = resolveKey.resolveKey(header1)

//Base 64 to base 58 multibase
        val b64pk = "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4="


        val publicKeyBytes = decodeFromBase64Url(b64pk)

        val edPk = byteArrayOf(0xED.toByte(), 0x01.toByte()) + publicKeyBytes

        val b58pk = Multibase.encode(Multibase.Base.Base58BTC, edPk)


        val pk = getPublicKeyObjectFromPublicKeyMultibase(b58pk)
        val messageBytes = "$header.$payload".toByteArray(StandardCharsets.UTF_8)
        val res = Signature.getInstance(CredentialVerifierConstants.ED25519_ALGORITHM, BouncyCastleProvider())
            .apply {
                initVerify(pk)
                update(messageBytes)

            }.verify(signature)

        println(res)
    }

    fun getPublicKeyObjectFromPublicKeyMultibase(publicKeyPem: String): PublicKey {
        try {
            val provider: BouncyCastleProvider = BouncyCastleProvider()

            val rawPublicKeyWithHeader = Base58.decode(publicKeyPem.substring(1))
            val rawPublicKey = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
            val publicKey = Hex.decode(DER_PUBLIC_KEY_PREFIX) + rawPublicKey
            val pubKeySpec = X509EncodedKeySpec(publicKey)
            val keyFactory = KeyFactory.getInstance("Ed25519", provider)
            return keyFactory.generatePublic(pubKeySpec)
        } catch (e: Exception) {
            throw PublicKeyNotFoundException("Public key object is null")
        }
    }


}
