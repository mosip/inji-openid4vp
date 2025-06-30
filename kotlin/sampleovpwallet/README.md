# Sample OVP Wallet

This is a sample Android application demonstrating how to integrate and use the inji-openid4vp Kotlin library to share Verifiable Credential (VC) presentation using OpenID for Verifiable Presentations (OpenID4VP) 
Formats supported:  
- LDP_VC : Implemented using [Specification-21](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html) and [Specification-23](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html)
- MSO_MDOC_VC: Implemented Using [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) and [ISO/IEC TS 18013-7](https://www.iso.org/standard/82772.html)

## Prerequisites

- Install Android Studio
- Install required SDK platforms and tools via SDK Manager in Android Studio which is expected tobe installed during Android Studio Installation
- Make sure Android Studio is configured to use JDK 17. It can be verified in Preferences → Build, Execution, Deployment → Build Tools → Gradle.
- Physical device to run the app, as QR code scanning requires camera access.


## Features

- Scans QR codes to receive Verifier Authorization Requests.
- Parses and validates incoming requests using inji-openid4vp.
- Selects matching VCs based on presentation definition constraints.
- Signs and sends Verifiable Presentations (VPs) to the Verifier.
- Error handling for declining or non-matching QR codes.

## Steps to run the app
- Hardcode the VC as downloading the VC is not part of the Sample App. (`io.mosip.sampleapp.data.HardcodedVC.kt`)
  - For `ldp_vc`, Update the Vc Json.
  - For `mso_mdoc` , update MDOC_CBOR_DATA.
- Update the `issuersList` accordingly in the shared View Model (`io.mosip.sampleapp.data.HardcodedVC.kt`) which mimics downloading the respective VC from the Issuer.
- Wallet Metadata and Verifiers list are hardcoded in the app. Update the `walletMetadata` and `verifiersList` in `io.mosip.sampleapp.data.HarcodedOVPData.kt` as per your requirements.
- Run the App
- Tap `+` icon in the home screen, Select Issuers to download the VC in the Home screen.
- Tap on `Share` bottom navigation, Scan the QR code. Grant necessary Camera permission. 
- If the VCs are not matching the auth request, Error popup will be shown.
- If the VCs matching the auth request, List of Credentials will be shown. User can select the VCs and tap on Share to send VP to Verifier.
- On successful sharing , Success Screen will be shown with `Home` Button. 

## Note
- This Sample app does not download or issue Verifiable Credentials (VCs). Therefore, holder binding is not part of this app.
- For Pre-registered scheme, we are not validating client as we are passing hardcoded `shouldValidateClient` flag as false