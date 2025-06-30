package io.mosip.openID4VP.testData

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPToken
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.constants.ClientIdScheme.DID
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED

const val requestUrl = "https://mock-verifier.com/verifier/get-auth-request-obj"
const val responseUrl = "https://mock-verifier.com/response-uri"
const val didUrl = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
const val mdocCredential =
    "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkCADCCAfwwggGjAhQF2zbegdWq1XHLmdrVZZIORS_efDAKBggqhkjOPQQDAjCBgDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoMBUlJSVRCMQwwCgYDVQQLDANEQ1MxEDAOBgNVBAMMB0NFUlRJRlkxIDAeBgkqhkiG9w0BCQEWEW1vc2lwcWFAZ21haWwuY29tMB4XDTI1MDIxMjEyMzE1N1oXDTI2MDIxMjEyMzE1N1owgYAxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEMMAoGA1UECwwDRENTMRAwDgYDVQQDDAdDRVJUSUZZMSAwHgYJKoZIhvcNAQkBFhFtb3NpcHFhQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAcZXrsgNSABzg9o_dNKu6S2pXuJ3hgYlX162Ex56IUGDJZP_IlRCrEQPHZSSl53DwlpL4iHisASqFaRQiXAtqkwCgYIKoZIzj0EAwIDRwAwRAIgGI6B63QccJQ4B84hRjRGlRURJ5SSNTuf74w-nE8zqRACIA3diiD3VCA5G6joGeTSX-Xx79shhDrCmUHuj3Lk5uL1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggwUwjgySYg2DOdGY4nNo0iwMhvWfX461qVPqRfzOSkLAGWCAqcNYwEHbJmU1HDkOtxjK_X-L6wsApZp6M68hP0409vANYIHvJF0gsS8tMyfvTgmIeEeLIL-wx50tcOjkJNGJUB7eaAVggeYDGTfx8w7Sz2hIQvkZ1QhtrXskhDjZkS_cgN6HP18oEWCBeZlkW29iqUBLxAFlOfHrz5qXioXKKaoyEEYI96YyKvwBYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIHXTzp8Von2hagU3QkJVjUyInx0bVtJ_jBEGgdg9i8_xIlggcu55Afxk6PuLoyhqtNVMr_C2H2tumM4fKr-fthKcg0dsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjUtMDQtMzBUMTE6NTQ6MzdaaXZhbGlkRnJvbcB0MjAyNS0wNC0zMFQxMTo1NDozN1pqdmFsaWRVbnRpbMB0MjAyNy0wNC0zMFQxMTo1NDozN1pYQMU-ji8KQVOtW-G8YJWadw4_ZSRpb56M4Xv8MUg9ivRqV3VIJpJ5tB55onmNLrVOao0OunClNsBP7iNvX8P3d-BqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjUtMDQtMzDYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMzAtMDQtMzDYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNS0wNC0zMCwgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMzAtMDQtMzB92BhYXaRoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVqOTI2MTQ4MTAyNNgYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYklO2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE="
val ldpCredential1 =
    convertJsonToMap(
        "{\"id\":\"did:rcw:38d51ff1-c55d-40be-af56-c3f30aaa81d4\",\"type\":[\"VerifiableCredential\",\"InsuranceCredential\"],\"proof\":{\"type\":\"Ed25519Signature2020\",\"created\":\"2025-05-12T10:51:03Z\",\"proofValue\":\"z62rZ8pWHi1PmkGYzZmgF8sQoLCPwwfvXYmSsC7P6KoaVyAoDv1SRi1VomcQqSv41HvkHKrHUfpJX3K3ZU9G1rVoh\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39#key-0\"},\"issuer\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39\",\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://holashchand.github.io/test_project/insurance-context.json\",\"https://w3id.org/security/suites/ed25519-2020/v1\"],\"issuanceDate\":\"2025-05-12T10:51:02.820Z\",\"expirationDate\":\"2025-06-11T10:51:02.814Z\",\"credentialSubject\":{\"id\":\"did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6Ii1zUVpsbDhYQXBySGVlNG5CdzB5TUwtLTdsOFJBNGhaM2dMclkzMzdtVUUiLCJhbGciOiJSUzI1NiIsIm4iOiJrUHllWHdIMVM3cjE3WmhOMkl3YmhZejR6bnNEVnl3bDdLRzllUjZ3bUM1YUtaZ0dyY18yWXB1V28tT2RuWDhOc3VWLWFzU0NjU01FVThVdUZqNWtienhRRGdPWFNQWlI1MHVCS19TVEtXTHNVenVlRHpQZUpGdDhibWItVjgtQ0FOa2JrSGRYbXVSS0pUU0JVd3lWRXdtTERnb0ZLYTlVLXhjVTVELWFDcHJFVS1fQ1oyUGZDcF9jdmtJNmdOS2FKRHJBcVVlUkVQYzAzbl93WXd0bE82S1RhQ25jc0JMbEp2U1NBM1B1ZEN5ZFFMVUZwak12R2d3VUlFNkg3d3FoTGdZeXZLTVBTYzVEMG8ybWZ0cHNTVFNrY3p2OEVPdnMtNU5kaHZXTXFlc0dtSE5helk5bDhOMFQyWGxrM0ZqM1lDcXNmQ1lnLUd1RkFRaXpZOU1ZV3cifQ==\",\"dob\":\"2025-01-01\",\"email\":\"abcd@gmail.com\",\"gender\":\"Male\",\"mobile\":\"0123456789\",\"benefits\":[\"Critical Surgery\",\"Full body checkup\"],\"fullName\":\"wallet\",\"policyName\":\"wallet\",\"policyNumber\":\"5555\",\"policyIssuedOn\":\"2023-04-20\",\"policyExpiresOn\":\"2033-04-20\"}}"
    )
val ldpCredential2 =
    convertJsonToMap(
        "{\"id\":\"did:rcw:da2d0059-cce8-4bad-923a-217cd381dbd2\",\"type\":[\"VerifiableCredential\",\"InsuranceCredential\"],\"proof\":{\"type\":\"Ed25519Signature2020\",\"created\":\"2025-05-12T10:51:44Z\",\"proofValue\":\"z3rACCjPw79KfPSYGasCVpqyWUpUhEYzPcmo2QLoVtj6LYUxpXi22UBcQdNSFbd3YedVrysS5Svzgcy1uYJEiVPKA\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39#key-0\"},\"issuer\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39\",\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://holashchand.github.io/test_project/insurance-context.json\",\"https://w3id.org/security/suites/ed25519-2020/v1\"],\"issuanceDate\":\"2025-05-12T10:51:44.739Z\",\"expirationDate\":\"2025-06-11T10:51:44.734Z\",\"credentialSubject\":{\"id\":\"did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6Ii1zUVpsbDhYQXBySGVlNG5CdzB5TUwtLTdsOFJBNGhaM2dMclkzMzdtVUUiLCJhbGciOiJSUzI1NiIsIm4iOiJrUHllWHdIMVM3cjE3WmhOMkl3YmhZejR6bnNEVnl3bDdLRzllUjZ3bUM1YUtaZ0dyY18yWXB1V28tT2RuWDhOc3VWLWFzU0NjU01FVThVdUZqNWtienhRRGdPWFNQWlI1MHVCS19TVEtXTHNVenVlRHpQZUpGdDhibWItVjgtQ0FOa2JrSGRYbXVSS0pUU0JVd3lWRXdtTERnb0ZLYTlVLXhjVTVELWFDcHJFVS1fQ1oyUGZDcF9jdmtJNmdOS2FKRHJBcVVlUkVQYzAzbl93WXd0bE82S1RhQ25jc0JMbEp2U1NBM1B1ZEN5ZFFMVUZwak12R2d3VUlFNkg3d3FoTGdZeXZLTVBTYzVEMG8ybWZ0cHNTVFNrY3p2OEVPdnMtNU5kaHZXTXFlc0dtSE5helk5bDhOMFQyWGxrM0ZqM1lDcXNmQ1lnLUd1RkFRaXpZOU1ZV3cifQ==\",\"dob\":\"2025-01-01\",\"email\":\"abcd@gmail.com\",\"gender\":\"Male\",\"mobile\":\"0123456789\",\"benefits\":[\"Critical Surgery\",\"Full body checkup\"],\"fullName\":\"wallet\",\"policyName\":\"wallet\",\"policyNumber\":\"5555\",\"policyIssuedOn\":\"2023-04-20\",\"policyExpiresOn\":\"2033-04-20\"}}"
    )

const val clientId = "client-id"
const val verifierNonce = "GM12ZywLxmA0PjQFevb/WQ=="
const val walletNonce = "P0RVGUe5OoDctvuK"

const val publicKey = """-----BEGIN RSA PUBLIC KEY-----publickey-----END RSA PUBLIC KEY-----"""
const val holderId = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdMbEJOQkstRmdicDBqaEVNUWx1MkkxV1dPeGtlZHRaYkVLalAtYndyYkkiLCJhbGciOiJFZDI1NTE5IiwidXNlIjoic2lnIn0#0"
const val signatureSuite = "JsonWebSignature2020"

const val jws = "eyJhbGciOiJFZERTQSIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImtldWxwNGVVU0d1eEVLSDlzQ0JkaTN1ek1sQmQ4cE1wMVdlamhTUFZybUEiLCJhbGciOiJFZDI1NTE5IiwidXNlIjoic2lnIn19..NGhwSDJoTktZT25kU2lVc3JwUEJoY1dld2JjT1FxQ2RsQW9qNFlENktMam9WT0M0N1RDMXk5cXFGTWpwZUVsMFhHeWNFZmpEd0s0N2pKOXFZOHFKRGc"
val ldpVPTokenSigningResult: LdpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws,
    null,
    signatureSuite

)
val mdocVPTokenSigningResult: MdocVPTokenSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication = mapOf(
        "org.iso.18013.5.1.mDL" to DeviceAuthentication(
            signature = "mdocsignature",
            algorithm = "ES256"
        )
    )
)

val ldpvpTokenSigningResults: Map<FormatType, VPTokenSigningResult> =
    mapOf(FormatType.LDP_VC to ldpVPTokenSigningResult)

val mdocvpTokenSigningResults: Map<FormatType, VPTokenSigningResult> =
    mapOf(FormatType.MSO_MDOC to mdocVPTokenSigningResult)

val unsignedLdpVPToken: UnsignedLdpVPToken = UnsignedLdpVPToken(
   dataToSign = "base64EncodedCanonicalisedData"
)
val unsignedMdocVPToken: UnsignedMdocVPToken = UnsignedMdocVPToken(
    docTypeToDeviceAuthenticationBytes = mapOf(
        "org.iso.18013.5.1.mDL" to "d8185892847444657669636541757468656e7469636174696f6e83f6f6835820ed084cf67d819fdc2ab6711e1a36053719358b46bfbf51a523c690f9cb6b1e5d5820ed084cf67d819fdc2ab6711e1a36053719358b46bfbf51a523c690f9cb6b1e5d7818624d487658314847686268387a716c5357662f6675513d3d756f72672e69736f2e31383031332e352e312e6d444cd81841a0"
    )
)

val clientMetadataMap = mapOf(
    "client_name" to "Requester name",
    "logo_uri" to "<logo_uri>",
    "authorization_encrypted_response_alg" to "ECDH-ES",
    "authorization_encrypted_response_enc" to "A256GCM",
    "vp_formats" to mapOf(
        "ldp_vc" to mapOf(
            "proof_type" to listOf(
                "Ed25519Signature2018",
                "Ed25519Signature2020"
            )
        )
    )
)

private val vpFormatsMap = mapOf(
    "ldp_vc" to VPFormatSupported(
        algValuesSupported = listOf("Ed25519Signature2018", "Ed25519Signature2020")
    )
)

val walletMetadata = WalletMetadata(
    presentationDefinitionURISupported = true,
    vpFormatsSupported = vpFormatsMap,
    clientIdSchemesSupported = listOf(
        ClientIdScheme.REDIRECT_URI.value,
        DID.value,
        PRE_REGISTERED.value
    ),
    requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
    authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
    authorizationEncryptionEncValuesSupported = listOf("A256GCM")
)

val clientMetadataString = """{
  "client_name": "Requester name",
  "logo_uri": "<logo_uri>",
  "authorization_encrypted_response_alg": "ECDH-ES",
  "authorization_encrypted_response_enc": "A256GCM",
  "jwks": {
    "keys": [
      {
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
        "alg": "ECDH-ES",
        "kid": "ed-key1"
      }
    ]
  },
  "vp_formats": {
      "ldp_vc": {
          "proof_type": [
          "Ed25519Signature2018",
          "Ed25519Signature2020"
          ]
      }
  }
}
""".trimIndent()

val presentationDefinitionMap = mapOf(
    "id" to "649d581c-f891-4969-9cd5-2c27385a348f",
    "input_descriptors" to listOf(
        mapOf(
            "id" to "idcardcredential",
            "format" to mapOf(
                "ldp_vc" to mapOf(
                    "proof_type" to listOf("Ed25519Signature2018")
                )
            ),
            "constraints" to mapOf(
                "fields" to listOf(
                    mapOf(
                        "path" to listOf("\$.type") // Escaped '$' as Kotlin requires '\$'
                    )
                )
            )
        )
    )
)

val presentationDefinitionString = """
    {
      "id": "649d581c-f891-4969-9cd5-2c27385a348f",
      "input_descriptors": [
        {
          "id": "idcardcredential",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "${'$'}.type"
                ]
              }
            ]
          }
        }
      ]
    }
""".trimIndent()

val didResponse = """
    {
      "@context": "https://w3id.org/did-resolution/v1",
      "didDocument": {
        "assertionMethod": [
          "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        ],
        "service": [],
        "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
        "verificationMethod": [
          {
            "publicKey": "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4=",
            "controller": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
            "type": "Ed25519VerificationKey2020",
            "@context": "https://w3id.org/security/suites/ed25519-2020/v1"
          }
        ],
        "@context": [
          "https://www.w3.org/ns/did/v1"
        ],
        "alsoKnownAs": [],
        "authentication": [
          "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        ]
      },
      "didResolutionMetadata": {
        "driverDuration": 19,
        "contentType": "application/did+ld+json",
        "pattern": "^(did:web:.+)${'$'}",
        "driverUrl": "http://uni-resolver-driver-did-uport:8081/1.0/identifiers/",
        "duration": 19,
        "did": {
          "didString": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "methodSpecificId": "mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "method": "web"
        },
        "didUrl": {
          "path": null,
          "fragment": null,
          "query": null,
          "didUrlString": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "parameters": null,
          "did": {
            "didString": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "methodSpecificId": "mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "method": "web"
          }
        }
      },
      "didDocumentMetadata": {}
    }
""".trimIndent()

val trustedVerifiers: List<Verifier> = listOf(
    Verifier(
        "mock-client", listOf(
            "https://mock-verifier.com/response-uri", "https://verifier.env2.com/responseUri"
        )
    ), Verifier(
        "mock-client2", listOf(
            "https://verifier.env3.com/responseUri", "https://verifier.env2.com/responseUri"
        )
    )
)

val authRequestParamsByReferenceDraft23 = listOf(
    CLIENT_ID.value,
    REQUEST_URI.value,
    REQUEST_URI_METHOD.value
)

val authRequestParamsByReferenceDraft21 = listOf(
    CLIENT_ID.value,
    CLIENT_ID_SCHEME.value,
    REQUEST_URI.value,
    REQUEST_URI_METHOD.value
)

val authRequestWithRedirectUriByValue = listOf(
    CLIENT_ID.value,
    RESPONSE_URI.value,
    RESPONSE_MODE.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value,
    CLIENT_METADATA.value
)

val authRequestWithPreRegisteredByValue = listOf(
    CLIENT_ID.value,
    RESPONSE_MODE.value,
    RESPONSE_URI.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value,
    CLIENT_METADATA.value
)

val authRequestWithDidByValue = listOf(
    CLIENT_ID.value,
    RESPONSE_MODE.value,
    RESPONSE_URI.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value,
    CLIENT_METADATA.value
)

val requestParams: Map<String, String> = mapOf(
    REDIRECT_URI.value to "https://mock-verifier.com",
    RESPONSE_URI.value to responseUrl,
    REQUEST_URI.value to requestUrl,
    REQUEST_URI_METHOD.value to "get",
    PRESENTATION_DEFINITION.value to presentationDefinitionString,
    PRESENTATION_DEFINITION_URI.value to "https://mock-verifier.com/verifier/get-presentation-definition",
    RESPONSE_TYPE.value to "vp_token",
    RESPONSE_MODE.value to "direct_post",
    NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
    STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
    CLIENT_METADATA.value to clientMetadataString
)

val authorisationRequestListToClientIdSchemeMap = mapOf(
    DID to authRequestWithDidByValue,
    ClientIdScheme.REDIRECT_URI to authRequestWithRedirectUriByValue,
    PRE_REGISTERED to authRequestWithPreRegisteredByValue
)

val clientIdOfDid = mapOf(
    CLIENT_ID.value to didUrl,
)

val clientIdOfPreRegistered = mapOf(
    CLIENT_ID.value to "mock-client",
)

val clientIdOfReDirectUriDraft23 = mapOf(
    CLIENT_ID.value to "${REDIRECT_URI.value}:https://mock-verifier.com/response-uri",
)

val clientIdOfReDirectUriDraft21 = mapOf(
    CLIENT_ID.value to "https://mock-verifier.com/response-uri",
)

val clientMetadataPresentationDefinitionMap = mapOf(
    PRESENTATION_DEFINITION.value to presentationDefinitionMap,
    CLIENT_METADATA.value to clientMetadataMap
)


val authorizationRequestForResponseModeJWT = AuthorizationRequest(
    clientId = "https://injiverify.dev2.mosip.net",
    responseType = "vp_token",
    responseMode = "direct_post.jwt",
    presentationDefinition = deserializeAndValidate(
        presentationDefinitionString,
        PresentationDefinitionSerializer
    ),
    responseUri = responseUrl,
    redirectUri = null,
    nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
    state = "fsnC8ixCs6mWyV+00k23Qg==",
    clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
)

val authorizationRequest = AuthorizationRequest(
    clientId = "https://mock-verifier.com",
    responseType = "vp_token",
    responseMode = "direct_post",
    presentationDefinition = deserializeAndValidate(
        presentationDefinitionMap,
        PresentationDefinitionSerializer
    ),
    responseUri = "https://mock-verifier.com",
    redirectUri = null,
    nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
    state = "fsnC8ixCs6mWyV+00k23Qg==",
    clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer)
)

val proof = Proof(
    type = "RsaSignature2018",
    created = "2024-02-13T10:00:00Z",
    challenge = "bMHvX1HGhbh8zqlSWf/fuQ==",
    domain = "https://123",
    proofValue = jws,
    proofPurpose = "authentication",
    verificationMethod = publicKey
)

val ldpVPToken = LdpVPToken(
    context = listOf("context"),
    type = listOf("type"),
    verifiableCredential = listOf(ldpCredential1, ldpCredential2, ldpCredential2),
    id = "id",
    holder = "holder",
    proof = proof
)

val vpTokenSigningPayload = VPTokenSigningPayload(
    context = listOf("context"),
    type = listOf("type"),
    verifiableCredential = listOf(ldpCredential1, ldpCredential2, ldpCredential2),
    id = "id",
    holder = "holder",
    proof = proof.apply {
        jws = null
        proofValue = null
    }
)

val unsignedVPTokens = mapOf(
    FormatType.LDP_VC to mapOf("vpTokenSigningPayload" to vpTokenSigningPayload, "unsignedVPToken" to unsignedLdpVPToken),
    FormatType.MSO_MDOC to mapOf("vpTokenSigningPayload" to listOf(mdocCredential), "unsignedVPToken" to unsignedMdocVPToken)
)

val mdocVPToken = MdocVPToken(
    base64EncodedDeviceResponse = "base64EncodedDeviceResponse",
)
val vpToken = VPTokenType.VPTokenElement(
    ldpVPToken
)

val presentationSubmission = PresentationSubmission(
    id = "ps_id",
    definitionId = "client_id",
    descriptorMap = listOf(
        DescriptorMap(
            id = "input_descriptor_1",
            format = "ldp_vp",
            path = "$",
            pathNested = PathNested(
                id = "input_descriptor_1",
                format = "ldp_vp",
                path = "$.verifiableCredential[0]"
            )
        )
    )
)
val authorizationResponse = AuthorizationResponse(
    presentationSubmission = presentationSubmission,
    vpToken = vpToken,
    state = "state"
)
