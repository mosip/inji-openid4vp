# INJI-OpenID4VP  

inji-openid4vp is an implementation of OpenID for Verifiable Presentations written in kotlin. It supports sharing of verifiable credentials with verifiers using the OpenID4VP protocol. 
Formats supported:  
- LDP_VC : Implemented using [Specification-21](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html) and [Specification-23](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html)
- MSO_MDOC_VC: Implemented Using [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) and [ISO/IEC TS 18013-7](https://www.iso.org/standard/82772.html)
  
Inji-OpenID4VP library is Kotlin Multiplatform Library which generates both AAR and JAR files for Android and Java based projects respectively.

The library validates the client_id and client_id_scheme parameters in the authorization request according to the relevant specification.
- If the client_id_scheme parameter is included in the authorization request, the request is treated as conforming to Draft 21, and validation is performed accordingly.
- If the client_id_scheme parameter is not included, the request is interpreted as following Draft 23, and validation is applied based on that specification.


**Table of Contents**

- [Installation](#installation)
- [APIs](#apis)
  - [authenticateVerifier](#authenticateverifier)
  - [constructUnsignedVPToken](#constructUnsignedVPToken)
  - [shareVerifiablePresentation](#shareverifiablepresentation)
  - [sendErrorToVerifier](#senderrortoverifier)


## Installation

Snapshot builds are available - 

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
val openID4VP = OpenID4VP(traceabilityId = "sample-id")
```

## APIs

### authenticateVerifier
- Receives a list of trusted verifiers & Verifier's encoded Authorization request from consumer app(mobile wallet).
- Optionally it also receives wallet metadata to be shared with the verifier.
- Decodes and parses the qr code data. Checks if the data contains request_uri or contains the entire Authorization request data entirely.
- If the data contains request_uri and request_uri_method as post, then the wallet metadata is shared in the request body while making an api call to request_uri for fetching authorization request.
- The library also validates the incoming authorization request with the wallet metadata
- Constructs the Authorization request object based on the client_id_scheme.
- Takes an optional boolean to toggle the client validation.
- Returns the validated Authorization request object.

**Note 1:** Wallet can send the entire metadata, library will customize it as per authorization request client_id_scheme. Eg - in case pre-registered, library modifies wallet metadata to be sent without request object signing info properties as specified in the specification.

**Note 2:** Currently the library does not support limit disclosure for any format of VC. It will throw an error if the request contains `presentation_definition` or `presentation_definition_uri` with `input_descriptors` and `limit_disclosure` set to required. 

#### WalletMetadata Parameters

| Parameter                                 | Type                        | Required   | Default Value      | Description                                                                                      |
|-------------------------------------------|-----------------------------|------------|--------------------|--------------------------------------------------------------------------------------------------|
| presentationDefinitionURISupported        | Bool                        | No         | true               | Indicates whether the wallet supports `presentation_definition_uri`.                             |
| vpFormatsSupported                        | [String: VPFormatSupported] | Yes        | N/A                | A dictionary specifying the supported verifiable presentation formats and their algorithms.      |
| clientIdSchemesSupported                  | List\<String\>              | No         | ["pre-registered"] | A list of supported client ID schemes.                                                           |
| requestObjectSigningAlgValuesSupported    | List\<String\>?             | No         | null               | A list of supported algorithms for signing request objects.                                      |
| authorizationEncryptionAlgValuesSupported | List\<String\>?             | No         | null               | A list of supported algorithms for encrypting authorization responses.                           |
| authorizationEncryptionEncValuesSupported | List\<String\>?             | No         | null               | A list of supported encryption methods for authorization responses.                              |



```
 val authenticationResponse = openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: String, trustedVerifierJSON: List<Verifier>,
 walletMetadata: WalletMetadata, shouldValidateClient: Bool)
```

###### Parameters

| Name                            | Type             | Description                                                                          |
|---------------------------------|------------------|--------------------------------------------------------------------------------------|
| urlEncodedAuthorizationRequest  | String           | URL encoded query parameter string containing the Verifier's authorization request   |
| trustedVerifiers                | List\<Verifier\> | A list of trusted Verifier objects each containing a clientId and a responseUri list |
| walletMetadata                  | WalletMetadata?  | Optional WalletMetadata to be shared with Verifier                                   |
| shouldValidateClient            | Bool?            | Optional Boolean to toggle client validation for pre-registered client id scheme     |

###### Example usage

```kotlin
val encodedAuthorizationRequest = ".../authorize?response_type=vp_token&client_id=redirect_uri%3Ahttps%3..."
val trustedVerifiers = listOf(Verifier("https://verify.env1.net",listOf("https://verify.env1.net/responseUri")))
val walletMetadata = WalletMetadata(
    presentationDefinitionURISupported = true,
    vpFormatsSupported = mapOf(
        "ldp_vc" to VPFormatSupported(
            algValuesSupported = listOf("Ed25519Signature2018", "Ed25519Signature2020")
        ),
        "mso_mdoc" to VPFormatSupported(
            algValuesSupported = listOf("ES256")
        )
    ),
    clientIdSchemesSupported = listOf("redirect_uri", "did", "pre-registered"),
    requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
    authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
    authorizationEncryptionEncValuesSupported = listOf("A256GCM")
)
val authorizationRequest: AuthorizationRequest = openID4VP.authenticateVerifier(
                    urlEncodedAuthorizationRequest = encodedAuthorizationRequest,
                    trustedVerifiers = trustedVerifiers,
                    walletMetadata = walletMetadata,
                    shouldValidateClient = true
                )
```

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

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### constructUnsignedVPToken
- Receives a map of input_descriptor id & list of verifiable credentials for each input_descriptor that are selected by the end-user.
- Creates a vp_token without proof using received input_descriptor IDs and verifiable credentials, then returns its string representation to consumer app(mobile wallet) for signing it.

```
    val unsignedVPTokens : Map<FormatType, UnsignedVPToken> = openID4VP.constructUnsignedVPToken(Map<String, Map<FormatType, List<Any>>>)    
```

###### Parameters

| Name                  | Type                                    | Description                                                                                                                                    |
|-----------------------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| verifiableCredentials | Map<String, Map<FormatType, List<Any>>> | A Map which contains input descriptor id as key and value is the map of credential format and the list of user selected verifiable credentials |

###### Example usage

```kotlin
 val unsignedVPTokens : Map<FormatType, UnsignedVPToken> = openID4VP.constructUnsignedVPToken(
            verifiableCredentials = mapOf(
                "input_descriptor_id" to mapOf(
                    FormatType.LDP_VC to listOf(
                        """credential1""",
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
- This function constructs a vp_token with proof using received VPTokenSigningResult, then sends it and the presentation_submission to the Verifier via a HTTP POST request.
- Returns the response back to the consumer app(mobile app) saying whether it has received the shared Verifiable Credentials or not.

**Note 1:** For MSO_MDOC credential, if multiple credentials are shared it is left on the verfier to map each credential to the corresponding input descriptor. The library does not provide this mapping as the ISO standard does not specify any such mapping.


```kotlin
    val response : String = openID4VP.shareVerifiablePresentation(vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>) 
```

###### Parameters

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

```
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

