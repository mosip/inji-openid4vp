package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ContentEncryptionAlgorithm
import io.mosip.openID4VP.constants.KeyManagementAlgorithm
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.VPFormatType

/**
 * This file contains default values for the WalletMetadata fields.
 * This has to be updated for any additional algorithm or format supported by the wallet.
 */

fun getDefaultResponseTypeSupported() =
    listOf(ResponseType.VP_TOKEN)

fun getDefaultRequestSigningAlgorithmSupported() =
    listOf(RequestSigningAlgorithm.EdDSA)

fun getDefaultKeyManagementAlgorithmSupported() =
    listOf(KeyManagementAlgorithm.ECDH_ES)

fun getDefaultContentEncryptionAlgorithmSupported() =
    listOf(ContentEncryptionAlgorithm.A256GCM)

fun getDefaultClientIdSchemesSupported() =
    listOf(ClientIdScheme.PRE_REGISTERED, ClientIdScheme.DID, ClientIdScheme.REDIRECT_URI)

fun getDefaultVpFormatsSupported() =
    mapOf(
        VPFormatType.LDP_VC to VPFormatSupported(
            algValuesSupported = emptyList()
        ),
        VPFormatType.LDP_VP to VPFormatSupported(
            algValuesSupported = emptyList()
        ),
        VPFormatType.MSO_MDOC to VPFormatSupported(
            algValuesSupported = emptyList()
        )
    )



