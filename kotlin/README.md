# INJI-OpenID4VP  


## 🚨 Breaking Changes

### From Version `release-0.4.x` onward:

### API contract changes
This library has undergone some changes in its API contract.

#### 1. Instantiation of OpenID4VP
- The OpenID4VP class is now initialized with `traceabilityId` and `walletMetadata` parameter, which is used to track the traceability of the requests and responses.

```kotlin
val openID4VP = OpenID4VP(traceabilityId = "trace-id", walletMetadata = walletMetadata)
```

#### 2. Construction of WalletMetadata
- The WalletMetdata construction has now been simplified. You can create a WalletMetadata object with the required parameters exposed as constants.
- In detail,
- `WalletMetadata` is now a struct that contains the following properties:
    - `presentationDefinitionURISupported`: Boolean
    - `vpFormatsSupported`: Map<String: VPFormatSupported>
    - `clientIdSchemesSupported`: List<ClientIdScheme>?
    - `requestObjectSigningAlgValuesSupported`: List<RequestSigningAlgorithm>?
    - `authorizationEncryptionAlgValuesSupported`: List<KeyManagementAlgorithm>?
    - `authorizationEncryptionEncValuesSupported`: List<ContentEncryptionAlgorithm>?

```kotlin
val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                FormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = listOf(ClientIdScheme.REDIRECT_URI, ClientIdScheme.PRE_REGISTERED),
            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
            authorizationEncryptionEncValuesSupported = listOf(ContentEncrytionAlgorithm.A256GCM)
        )
```

3. The shouldValidateClient parameter in authenticateVerifier now defaults to true.
- If your integration previously relied on it being false, you must now explicitly pass false to preserve the old behavior.
- Example (updated usage)
```kotlin
val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
                    urlEncodedAuthorizationRequest = encodedAuthorizationRequest,
                    trustedVerifiers = trustedVerifiers,
                    shouldValidateClient = true
                )
```


#### ❗ Required Update in Imports

Replace:

```kotlin
import io.mosip.openID4VP.dto.Verifier;
import io.mosip.openID4VP.dto.vpResponseMetadata.VPResponseMetadata;
```

With:

```kotlin
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata;
```

## API contract changes

- This library has undergone significant changes in its API contract. The new API contracts are designed to be more flexible and extensible, allowing for support of multiple verifiable credential formats. The changes are discussed in the [API section](#apis) below.
- Backward compatibility of all the APIs with the previous version of the library has been maintained.


## **Introduction**

inji-openid4vp is an implementation of OpenID for Verifiable Presentations written in kotlin. It supports sharing of verifiable credentials with verifiers using the OpenID4VP protocol. 
Formats supported:  
- LDP_VC : Implemented using [Specification-21](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html) and [Specification-23](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html)
- MSO_MDOC_VC: Implemented Using [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) and [ISO/IEC TS 18013-7](https://www.iso.org/standard/82772.html)
  
Inji-OpenID4VP library is Kotlin Multiplatform Library which generates both AAR and JAR files for Android and Java based projects respectively.

The library validates the client_id and client_id_scheme parameters in the authorization request according to the relevant specification.
- If the client_id_scheme parameter is included in the authorization request, the request is treated as conforming to Draft 21, and validation is performed accordingly.
- If the client_id_scheme parameter is not included, the request is interpreted as following Draft 23, and validation is applied based on that specification.


## **Table of Contents**

- [Installation](#installation)
- [Integration](#integration)
- [Package Structure](#package-structure)
- [APIs](#apis)
  - [authenticateVerifier](#authenticateverifier)
  - [constructUnsignedVPToken](#constructUnsignedVPToken)
  - [shareVerifiablePresentation](#shareverifiablepresentation)
  - [sendErrorToVerifier](#senderrortoverifier)


## Installation

## For Android Based Projects

```
implementation "io.mosip:inji-openid4vp-aar:0.4.0-SNAPSHOT"
```

## For Java Based Projects

```
implementation "io.mosip:inji-openid4vp-jar:0.4.0-SNAPSHOT"
```

## Create instance of OpenID4VP library to invoke it's methods

```kotlin
val openID4VP = OpenID4VP(traceabilityId = "trace-id", walletMetadata = walletMetadata)
```
###### Parameters
| Name           | Type           | Description                                                                                                                                                                                                     |
|----------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| traceabilityId | String         | Unique identifier for tracking requests and responses.                                                                                                                                                          |
| walletMetadata | WalletMetadata | Metadata which wallet supports, such that client-id-scheme support, vp format support, proof type support, etc. 


## Integration
- To integrate the inji-openid4vp library into your Android application, there is a sample application created in `kotlin/sampleovpwallet` directory. This sample app demonstrates how to use the library to authenticate Verifiers, construct unsigned Verifiable Presentation (VP) tokens, and share them with Verifiers.
- For more details refer to [README](https://github.com/mosip/inji-openid4vp/blob/release-0.3.x/kotlin/sampleovpwallet/README.md) of the sample application.

## Package Structure
```
io.mosip.openID4VP/
├── OpenID4VP.kt                  # Main library class with public APIs
│
├── authorizationRequest/         # Authorization request handling
│   ├── AuthorizationRequest.kt   # Model for parsed authorization requests
│   ├── Verifier.kt               # Trusted verifier model
│   ├── clientMetadata/
│   │   ├── ClientMetadata.kt     # Client metadata model
│   │   ├── Jwk.kt                # JSON Web Key model
│   │   └── Jwks.kt               # JSON Web Key Set model
│   └── presentationDefinition/   # Presentation definition models
│       ├── PresentationDefinition.kt
│       ├── InputDescriptor.kt
│       ├── Constraints.kt
│       │   └── Fields.kt   
│       │       └── Filter.kt       
│
├── authorizationResponse/        # Response handling
│   ├── AuthorizationResponse.kt  # Model for authorization responses
│   ├── presentationSubmission/  # Presentation submission models
│   │   ├── PresentationSubmission.kt 
│   │   └── DescriptorMapping.kt
│   │
│   ├── unsignedVPToken/            # Unsigned VP token models
│   │   ├── UnsignedVPToken.kt    # Base class for unsigned tokens
│   │   ├── types/
│   │   │   ├── ldp/              # JSON-LD format support
│   │   │   │   └── UnsignedLdpVPToken.kt
│   │   │   └── mdoc/             # mDOC format support
│   │   │       └── UnsignedMdocVPToken.kt
│   │
│   ├── vpToken/                  # VP token models
│   │   ├── VPToken.kt             # Base class for VP tokens
│   │   ├── types/
│   │   │   ├── ldp/              # JSON-LD format support
│   │   │   │   └── LdpVPToken.kt
│   │   │   └── mdoc/             # mDOC format support
│   │   │       └── MdocVPToken.kt
│   │
│   └── vpTokenSigningResult/     # Signing results models
│       ├── VPTokenSigningResult.kt # Base interface
│       ├── types/
│       │   ├── ldp/              # JSON-LD format support
│       │   │   └── LdpVPTokenSigningResult.kt
│       │   └── mdoc/             # mDOC format support
│       │       └── MdocVPTokenSigningResult.kt
│
├── common/                       # Common utilities and models
├── constants/                    # Constants used across the library  
│
├── jwt/                          # JWT handling
│   ├── jwe/                      # JWE encryption support
│   │   ├── JWEHandler.kt         # Handles JWE operations
│   │   └── encryption/
│   │       └── EncryptionProvider.kt # Provides encryption services
│   ├── jws/                      # JWS signature support
│       └── JWSHandler.kt         # Handles JWS operations
│   ├──keyResolver/          # Resolves keys for JWT operations
│   │   ├── types/
│   │   │   ├── DidPublicKeyResolver.kt  
│   │   └── PublicKeyResolver.kt       # Base class for public key resolution
│
├── exceptions/                   # Exceptions
│   └── OpenID4VPExceptions.kt    # Centralized exception definitions
```

## APIs

### authenticateVerifier
- Accepts a URL-encoded Authorization Request from the Verifier and a list of trusted Verifiers provided by the consumer app (e.g., mobile wallet).
- Optionally accepts wallet metadata to be shared with the verifier.
- Decodes and parses the QR code data to determine if it contains a `request_uri` or the complete Authorization Request data.
- If the data contains `request_uri` and `request_uri_method` as POST, the wallet metadata is included in the request body when making an API call to fetch the Authorization Request.
- Validates the incoming authorization request with the provided wallet metadata.
- Constructs the Authorization request object based on the `client_id_scheme`.
- Includes an optional boolean parameter to enable or disable client validation.
- Sets the response URI for communication with the verifier.
- Returns the validated Authorization request object.

**Note 1:** Wallet can send the entire metadata, library will customize it as per authorization request client_id_scheme. Eg - in case pre-registered, library modifies wallet metadata to be sent without request object signing info properties as specified in the specification.

**Note 2:** Currently the library does not support limit disclosure for any format of VC. It will throw an error if the request contains `presentation_definition` or `presentation_definition_uri` with `input_descriptors` and `limit_disclosure` set to required. 


``` kotlin
//NOTE: New API contract
 val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
                                    urlEncodedAuthorizationRequest: String, 
                                    trustedVerifierJSON: List<Verifier>,
                                    shouldValidateClient: Boolean = false,
                                    walletMetadata: WalletMetadata? = null)
                                    
//NOTE: Old API contract for backward compatibility
 val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
                                    urlEncodedAuthorizationRequest: String, 
                                    trustedVerifierJSON: List<Verifier>,
                                    shouldValidateClient: Boolean = false)
```

###### Request Parameters

| Name                            | Type             | Description                                                                                               |
|---------------------------------|------------------|-----------------------------------------------------------------------------------------------------------|
| urlEncodedAuthorizationRequest  | String           | URL encoded query parameter string containing the Verifier's authorization request                        |
| trustedVerifiers                | List\<Verifier\> | A list of trusted Verifier objects each containing a clientId and a responseUri list                      |
| walletMetadata                  | WalletMetadata?  | Nullable WalletMetadata to be shared with Verifier                                                        |
| shouldValidateClient            | Boolean?         | Nullable Boolean with default value false to toggle client validation for pre-registered client id scheme |

###### Response 
```kotlin
val authorizationRequest = AuthorizationRequest(
    clientId = "https://mock-verifier.com",
    responseType = "vp_token",
    responseMode = "direct_post",
    presentationDefinition = PresentationDefinition(
        id = "649d581c-f891-4969-9cd5-2c27385a348f",
        inputDescriptors = listOf(
            InputDescriptor(
                id = "id card credential",
                format = mapOf(
                    "ldp_vc" to mapOf(
                        "proof_type" to listOf("Ed25519Signature2018")
                    )
                ),
                constraints = Constraints(
                    fields = listOf(
                        Fields(path = listOf("\$.type"))
                    )
                )
            )
        )
    ),
    responseUri = "https://mock-verifier.com",
    redirectUri = null,
    nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
    state = "fsnC8ixCs6mWyV+00k23Qg==",
    clientMetadata = ClientMetadata(
        clientName = "Requester name",
        logoUri = "<logo_uri>",
        authorizationEncryptedResponseAlg = "ECDH-ES",
        authorizationEncryptedResponseEnc = "A256GCM",
        vpFormats = mapOf(
            "ldp_vc" to mapOf(
                "algValuesSupported" to listOf("Ed25519Signature2018", "Ed25519Signature2020")
            )
        ),
        jwks = Jwks(
            keys = listOf(
                Jwk(
                    kty = "OKP",
                    crv = "X25519",
                    use = "enc",
                    x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    alg = "ECDH-ES",
                    kid = "ed-key1"
                )
            )
        )
    )
)
```
###### Example usage

```kotlin
val encodedAuthorizationRequest = ".../authorize?response_type=vp_token&client_id=redirect_uri%3Ahttps%3..."
val trustedVerifiers = listOf(Verifier("https://verify.env1.net",listOf("https://verify.env1.net/responseUri")))
val walletMetadata = WalletMetadata(
    presentationDefinitionURISupported = true,
    vpFormatsSupported = mapOf(
        FormatType.LDP_VC to VPFormatSupported(
            algValuesSupported = listOf("EdDSA")
        )
    ),
    clientIdSchemesSupported = listOf(ClientIdScheme.REDIRECT_URI, ClientIdScheme.PRE_REGISTERED),
    requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
    authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
    authorizationEncryptionEncValuesSupported = listOf(ContentEncrytionAlgorithm.A256GCM)
)
val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
                    urlEncodedAuthorizationRequest = encodedAuthorizationRequest,
                    trustedVerifiers = trustedVerifiers,
                    shouldValidateClient = true
                )
```

#### WalletMetadata Parameters

| Parameter                                 | Type                                 | Required   | Default Value    | Description                                                                                      |
|-------------------------------------------|--------------------------------------|------------|------------------|--------------------------------------------------------------------------------------------------|
| presentationDefinitionURISupported        | Boolean                              | No         | true             | Indicates whether the wallet supports `presentation_definition_uri`.                             |
| vpFormatsSupported                        | Map\<FormatType: VPFormatSupported\> | Yes        | N/A              | A dictionary specifying the supported verifiable presentation formats and their algorithms.      |
| clientIdSchemesSupported                  | List\<ClientIdScheme\>               | No         | "pre-registered" | A list of supported client ID schemes.                                                           |
| requestObjectSigningAlgValuesSupported    | List\<RequestSigningAlgorithm\>?     | No         | null             | A list of supported algorithms for signing request objects.                                      |
| authorizationEncryptionAlgValuesSupported | List\<KeyManagementAlgorithm\>?      | No         | null             | A list of supported algorithms for encrypting authorization responses.                           |
| authorizationEncryptionEncValuesSupported | List\<ContentEncrytionAlgorithm\>?   | No         | null             | A list of supported encryption methods for authorization responses.                              |

#### Verifier Parameters

| Parameter                                   | Type                             | Required                     | Description                                                                                       |
|---------------------------------------------|----------------------------------|------------------------------|---------------------------------------------------------------------------------------------------|
| clientId                                    | String                           | Yes                          | The unique identifier for the Verifier.                                                           |
| responseUri                                 | List\<String\>                   | Yes                          | A list of URIs where the Verifier can receive responses from the wallet.                          |



###### Exceptions

1. DecodingException is thrown when there is an issue while decoding the Authorization Request
2. InvalidQueryParams exception is thrown if
   * query params are not present in the Request
   * there is an issue while extracting the params
   * both presentation_definition and presentation_definition_uri are present in Request
   * both presentation_definition and presentation_definition_uri are not present in Request
3. MissingInput exception is thrown if any of required params are not present in Request
4. InvalidInput exception is thrown if any of required params value is empty or null
5. InvalidVerifier exception is thrown if the received request client_iD & response_uri are not matching with any of the trusted verifiers
6. JWTVerification exception is thrown if there is any error in extracting public key, kid or signature verification failure. 
7. InvalidData exception is thrown if
    - `response_mode` is not supported
    - For `direct_post.jwt` response mode
        - client_metadata is not available
        - unable to find the public key JWK from the `jwks` of `client_metadata` as per the provided algorithm in `client_metadata`
   - `publicKeyMultibase` is null or empty
8. UnsupportedPublicKeyType exception is thrown when the public key type is not `publicKeyMultibase`.
9. PublicKeyExtractionFailed exception is thrown when there are any errors in extracting the public key from verification method

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


##### Exception Handling Enhancement

- The library has been enhanced to handle exceptions more gracefully. Library is throwing `OpenID4VPExceptions` now which gives both Error Code, Message and optional state to the consumer app. The `state` value is extracted from the authorization request and is included in the error response only if it is present and non-empty. This allows the consumer app to handle exceptions more effectively and provide better user experience.
- For the backward compatibility, the library will still throw the exceptions with `message` which can be referred in sample application `io.mosip.sampleapp.utils.OpenID4VPManager`. However, it is recommended to use the new `OpenID4VPExceptions` for better error handling.


### constructUnsignedVPToken
- This method creates unsigned Verifiable Presentation (VP) tokens from a collection of Verifiable Credentials. It:  
  - Takes credentials organized by input descriptor IDs and formats along with the holder's identifier, and the signature suite to be used for signing the VP tokens.
  - Creates format-specific VP tokens (supporting JSON-LD and  mDOC formats)
  - Returns a map of unsigned VP tokens organized by format type
- The tokens returned are ready for digital signing **to be signed by wallet** before being shared with verifiers in an OpenID4VP flow.

```kotlin
    //NOTE: New API contract
    val unsignedVPTokens : Map<FormatType, UnsignedVPToken> = openID4VP.constructUnsignedVPToken(Map<String, Map<FormatType, List<Any>>>)

    //NOTE: Old API contract for backward compatibility
    val unsignedVPTokens : String = openID4VP.constructUnsignedVPToken(Map<String, List<String>>)
```

###### Request Parameters

| Name                  | Type                                    | Description                                                                                                                                    |
|-----------------------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| verifiableCredentials | Map<String, Map<FormatType, List<Any>>> | A Map which contains input descriptor id as key and value is the map of credential format and the list of user selected verifiable credentials |


###### Response Parameters
```kotlin
//NOTE: New API contract Response
val unsignedLdpVpTokens: Map<FormatType, UnsignedVPToken> = mapOf(
    FormatType.LDP_VC to UnsignedLdpVPToken(
        dataToSign = "base64EncodedCanonicalisedData", // This should be the actual base64 encoded canonicalized data of the VP token
    ),
    FormatType.MSO_MDOC to UnsignedMdocVPToken(
        docTypeToDeviceAuthenticationBytes = mapOf(
            "org.iso.18013.5.1.mDL" to "<docTypeToDeviceAuthenticationBytes>" // This should be the actual base64 encoded bytes of the device authentication
        )
    )
)

//NOTE: Old API contract Response
val unsignedVPToken: String = """
    {
          "@context": ["context-url"],
          "type": ["type"],
          "verifiableCredential": [
            "ldpCredential1",
            "ldpCredential2"
          ],
          "id": "id",
          "holder": "holder"
    }
"""
```


###### Example usage

```kotlin
 val unsignedVPTokens : Map<FormatType, UnsignedVPToken> = openID4VP.constructUnsignedVPToken(
            verifiableCredentials = mapOf(
                "input_descriptor_id" to mapOf(
                    FormatType.LDP_VC to listOf(
                        <ldp-vc-json>,
                    )
                ),
                "input_descriptor_id" to mapOf(
                    FormatType.MSO_MDOC to listOf(
                        "credential2",
                    )
                )
            )
        )
```

###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.
2. InvalidData exception is thrown if provided verifiable credentials list is empty

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### shareVerifiablePresentation
- Constructs a `vp_token` with proof using the provided `VPTokenSigningResult`, then sends it along with the `presentation_submission` to the Verifier via an HTTP POST request.
- Returns a response to the consumer app (e.g., mobile app) indicating whether the Verifiable Credentials were successfully shared with the Verifier.

**Note 1:** When sharing multiple MSO_MDOC credentials, the verifier is responsible for mapping each credential to its corresponding input descriptor. This mapping is not handled by the library since the ISO standard does not define such a mapping mechanism.


```kotlin
//NOTE: New API contract
    val response : String = openID4VP.shareVerifiablePresentation(vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>) 

//NOTE: Old API contract for backward compatibility
    val response : String = openID4VP.shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata)
```

###### Request Parameters

| Name                    | Type                                  | Description                                                                                                                                                   |
|-------------------------|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | Map<FormatType, VPTokenSigningResult> | This will be a map with key as credential format and value as VPTokenSigningResult (which is specific to respective credential format's required information) |


##### Example usage

```kotlin
 val ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws = "ey....qweug",
    signatureAlgorithm = "RsaSignature2018",
    publicKey = publicKey,
    domain = "<domain>"
)
val mdocVPTokenSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication = mapOf(
        "<mdoc-docType>" to DeviceAuthentication(
            signatue = "ey....qweug",
            algorithm = "ES256",
        )
    )
)
val vpTokenSigningResults : Map<FormatType, VPTokenSigningResult> = mapOf(
    FormatType.LDP_VC to ldpVPTokenSigningResult,
    FormatType.MSO_MDOC to mdocVPTokenSigningResult
)
val response : String = openID4VP.shareVerifiablePresentation(vpTokenSigningResults = vpTokenSigningResults)
```


###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. InterruptedIOException is thrown if the connection is timed out when network call is made.
3. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.
4. InvalidData exception is thrown if the response_type in the authorization request is not supported

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### sendErrorToVerifier
- Receives an exception and sends it's message to the Verifier via an HTTP POST request.

```kotlin
 openID4VP.sendErrorToVerifier(exception: Exception)
```

###### Parameters

| Name      | Type      | Description                        |
|-----------|-----------|------------------------------------|
| exception | Exception | This contains the exception object |

###### Example usage

```kotlin
openID4VP.sendErrorToVerifier(Exception("User did not give consent to share the requested Credentials with the Verifier."))
```

###### Exceptions

1. InterruptedIOException is thrown if the connection is timed out when network call is made.
2. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.

