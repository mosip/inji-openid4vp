package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlin.test.*

class WalletMetadataTest {

    @Test
    fun `should create WalletMetadata with primary constructor`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = false,
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA", "ES256")
                )
            ),
            clientIdSchemesSupported = listOf(ClientIdScheme.DID),
            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
            authorizationEncryptionEncValuesSupported = listOf(ContentEncryptionAlgorithm.A256GCM),
            responseTypeSupported = listOf(ResponseType.VP_TOKEN)
        )

        assertEquals(false, walletMetadata.presentationDefinitionURISupported)
        assertEquals(1, walletMetadata.vpFormatsSupported?.size)
        assertEquals(listOf("EdDSA", "ES256"), walletMetadata.vpFormatsSupported?.get(VPFormatType.LDP_VC)?.algValuesSupported)
        assertEquals(listOf(ClientIdScheme.DID), walletMetadata.clientIdSchemesSupported)
        assertEquals(listOf(RequestSigningAlgorithm.EdDSA), walletMetadata.requestObjectSigningAlgValuesSupported)
        assertEquals(listOf(KeyManagementAlgorithm.ECDH_ES), walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertEquals(listOf(ContentEncryptionAlgorithm.A256GCM), walletMetadata.authorizationEncryptionEncValuesSupported)
        assertEquals(listOf(ResponseType.VP_TOKEN), walletMetadata.responseTypeSupported)
    }

    @Test
    fun `should create WalletMetadata with default constructor`() {
        val walletMetadata = WalletMetadata()

        assertTrue(walletMetadata.presentationDefinitionURISupported)
        assertNotNull(walletMetadata.vpFormatsSupported)
        assertNotNull(walletMetadata.clientIdSchemesSupported)
        assertNotNull(walletMetadata.requestObjectSigningAlgValuesSupported)
        assertNotNull(walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertNotNull(walletMetadata.authorizationEncryptionEncValuesSupported)
        assertNotNull(walletMetadata.responseTypeSupported)
    }

    @Test
    fun `should create WalletMetadata with deprecated constructor`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = false,
            vpFormatsSupported = mapOf(
                "LDP_VC" to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA", "ES256")
                )
            ),
            clientIdSchemesSupported = listOf("DID"),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH_ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )

        assertEquals(false, walletMetadata.presentationDefinitionURISupported)
        assertEquals(1, walletMetadata.vpFormatsSupported?.size)
        assertEquals(listOf("EdDSA", "ES256"), walletMetadata.vpFormatsSupported?.get(VPFormatType.LDP_VC)?.algValuesSupported)
        assertEquals(listOf(ClientIdScheme.DID), walletMetadata.clientIdSchemesSupported)
        assertEquals(listOf(RequestSigningAlgorithm.EdDSA), walletMetadata.requestObjectSigningAlgValuesSupported)
        assertEquals(listOf(KeyManagementAlgorithm.ECDH_ES), walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertEquals(listOf(ContentEncryptionAlgorithm.A256GCM), walletMetadata.authorizationEncryptionEncValuesSupported)
    }

    @Test
    fun `should throw exception for invalid enum values in deprecated constructor`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                vpFormatsSupported = mapOf(
                    "INVALID_FORMAT" to VPFormatSupported(
                        algValuesSupported = listOf("EdDSA")
                    )
                )
            )
        }

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                vpFormatsSupported = mapOf(
                    "LDP_VC" to VPFormatSupported(
                        algValuesSupported = listOf("EdDSA")
                    )
                ),
                clientIdSchemesSupported = listOf("INVALID_SCHEME")
            )
        }

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                vpFormatsSupported = mapOf(
                    "LDP_VC" to VPFormatSupported(
                        algValuesSupported = listOf("EdDSA")
                    )
                ),
                requestObjectSigningAlgValuesSupported = listOf("INVALID_ALG")
            )
        }
    }

    @Test
    fun `should parse enum values correctly`() {
        assertEquals(
            VPFormatType.LDP_VC,
            WalletMetadata.parseEnum("LDP_VC", VPFormatType.entries.toTypedArray(), "VPFormatType")
        )

        assertEquals(
            ClientIdScheme.DID,
            WalletMetadata.parseEnum("DID", ClientIdScheme.entries.toTypedArray(), "ClientIdScheme")
        )

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata.parseEnum("INVALID", VPFormatType.entries.toTypedArray(), "VPFormatType")
        }
    }

    @Test
    fun `should create VPFormatSupported with null algValuesSupported`() {
        val vpFormatSupported = VPFormatSupported(null)
        assertNull(vpFormatSupported.algValuesSupported)
    }

    @Test
    fun `should compare WalletMetadata objects correctly`() {
        val metadata1 = WalletMetadata(
            presentationDefinitionURISupported = false,
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            )
        )

        val metadata2 = WalletMetadata(
            presentationDefinitionURISupported = false,
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            )
        )

        val metadata3 = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            )
        )

        assertEquals(metadata1, metadata2)
        assertNotEquals(metadata1, metadata3)
    }

    @Test
    fun `should handle null values in WalletMetadata constructor`() {
        val walletMetadata = WalletMetadata(
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = null,
            requestObjectSigningAlgValuesSupported = null,
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = null,
            responseTypeSupported = null
        )

        assertNotNull(walletMetadata.vpFormatsSupported)
        assertNotNull(walletMetadata.clientIdSchemesSupported)
        assertNotNull(walletMetadata.requestObjectSigningAlgValuesSupported)
        assertNotNull(walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertNotNull(walletMetadata.authorizationEncryptionEncValuesSupported)
        assertNotNull(walletMetadata.responseTypeSupported)
    }
}