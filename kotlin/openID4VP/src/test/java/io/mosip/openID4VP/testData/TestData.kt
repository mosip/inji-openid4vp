package io.mosip.openID4VP.testData

import io.mosip.openID4VP.authorizationRequest.ClientIdScheme
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*

const val requestUrl = "https://mock-verifier.com/verifier/get-auth-request-obj"

val clientMetadata = """
    {
  "client_name": "Requester name",
  "logo_uri": "<logo_uri>",
  "authorization_encrypted_response_alg": "ECDH-ES",
  "authorization_encrypted_response_enc": "A256GCM",
  "vp_formats": {
    "mso_mdoc": {
      "alg": [
        "ES256",
        "EdDSA"
      ]
    },
    "ldp_vp": {
      "proof_type": [
        "Ed25519Signature2018",
        "Ed25519Signature2020",
        "RsaSignature2018"
      ]
    }
  }
}
""".trimIndent()

val presentationDefinition = """
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
        "https://verifier.env1.net", listOf(
            "https://verifier.env1.net/responseUri", "https://verifier.env2.net/responseUri"
        )
    ), Verifier(
        "https://verifier.env2.net", listOf(
            "https://verifier.env3.net/responseUri", "https://verifier.env2.net/responseUri"
        )
    )
)

val authRequestParamsByReference = listOf(
    CLIENT_ID.value,
    CLIENT_ID_SCHEME.value,
    REQUEST_URI.value,
    REQUEST_URI_METHOD.value
)

val authRequestWithRedirectUriByValue = listOf(
    CLIENT_ID.value,
    CLIENT_ID_SCHEME.value,
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
    CLIENT_ID_SCHEME.value,
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
    CLIENT_ID_SCHEME.value,
    RESPONSE_MODE.value,
    RESPONSE_URI.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value,
    CLIENT_METADATA.value
)

val requestParams: Map<String, String> = mapOf(
    CLIENT_ID.value to "https://mock-verifier.com",
    CLIENT_ID_SCHEME.value to "pre-registered",
    REDIRECT_URI.value to "https://mock-verifier.com",
    RESPONSE_URI.value to "https://verifier.env1.net/responseUri",
    REQUEST_URI.value to requestUrl,
    REQUEST_URI_METHOD.value to "get",
    PRESENTATION_DEFINITION.value to presentationDefinition,
    PRESENTATION_DEFINITION_URI.value to "https://mock-verifier.com/verifier/get-presentation-definition",
    RESPONSE_TYPE.value to "vp_token",
    RESPONSE_MODE.value to "direct_post",
    NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
    STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
    CLIENT_METADATA.value to clientMetadata
)

val authorisationRequestListToClientIdSchemeMap = mapOf(
    ClientIdScheme.DID to authRequestWithDidByValue,
    ClientIdScheme.REDIRECT_URI to authRequestWithRedirectUriByValue,
    ClientIdScheme.PRE_REGISTERED to authRequestWithPreRegisteredByValue
)

val clientIdAndSchemeOfDid = mapOf(
    CLIENT_ID.value to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
    CLIENT_ID_SCHEME.value to ClientIdScheme.DID.value
)

val clientIdAndSchemeOfPreRegistered = mapOf(
    CLIENT_ID.value to "https://verifier.env1.net",
    CLIENT_ID_SCHEME.value to ClientIdScheme.PRE_REGISTERED.value
)

val clientIdAndSchemeOfReDirectUri = mapOf(
    CLIENT_ID.value to "https://verifier.env1.net/responseUri",
    CLIENT_ID_SCHEME.value to REDIRECT_URI.value,
)