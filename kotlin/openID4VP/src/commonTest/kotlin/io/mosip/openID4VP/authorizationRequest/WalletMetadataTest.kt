//package io.mosip.openID4VP.authorizationRequest
//
//import io.mosip.openID4VP.constants.ClientIdScheme
//import io.mosip.openID4VP.constants.ContentEncryptionAlgorithm
//import io.mosip.openID4VP.constants.KeyManagementAlgorithm
//import io.mosip.openID4VP.constants.RequestSigningAlgorithm
//import io.mosip.openID4VP.constants.VPFormatType
//import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
//import kotlin.test.*
//
//class WalletMetadataTest {
//
//    @Test
//    fun `should create WalletMetadata with all parameters provided`() {
//        val walletMetadata = WalletMetadata(
//            presentationDefinitionURISupported = false,
//            vpFormatsSupported = mapOf(
//                VPFormatType.LDP_VC to VPFormatSupported(
//                    algValuesSupported = listOf("EdDSA", "ES256")
//                )
//            ),
//            clientIdSchemesSupported = listOf(ClientIdScheme.DID),
//            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
//            authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
//            authorizationEncryptionEncValuesSupported = listOf(ContentEncryptionAlgorithm.A256GCM)
//        )
//
//        assertEquals(false, walletMetadata.presentationDefinitionURISupported)
//        assertEquals(1, walletMetadata.vpFormatsSupported?.size)
//        assertEquals(listOf("EdDSA", "ES256"), walletMetadata.vpFormatsSupported?.get(VPFormatType.LDP_VC)?.algValuesSupported)
//        assertEquals(listOf(ClientIdScheme.DID), walletMetadata.clientIdSchemesSupported)
//        assertEquals(listOf(RequestSigningAlgorithm.EdDSA), walletMetadata.requestObjectSigningAlgValuesSupported)
//        assertEquals(listOf(KeyManagementAlgorithm.ECDH_ES), walletMetadata.authorizationEncryptionAlgValuesSupported)
//        assertEquals(listOf(ContentEncryptionAlgorithm.A256GCM), walletMetadata.authorizationEncryptionEncValuesSupported)
//    }
//
//    @Test
//    fun `should create WalletMetadata with construct method`() {
//        val walletMetadata = WalletMetadata.construct(
//            mapOf(
//                VPFormatType.LDP_VC to listOf("EdDSA"),
//            )
//        )
//
//        assertEquals(true, walletMetadata.presentationDefinitionURISupported)
//        assertEquals(1, walletMetadata.vpFormatsSupported.size)
//        assertEquals(listOf("EdDSA"), walletMetadata.vpFormatsSupported[VPFormatType.LDP_VC]?.algValuesSupported)
//        assertEquals(3, walletMetadata.clientIdSchemesSupported?.size)
//        assertTrue(walletMetadata.clientIdSchemesSupported?.contains(ClientIdScheme.PRE_REGISTERED) == true)
//        assertTrue(walletMetadata.clientIdSchemesSupported?.contains(ClientIdScheme.DID) == true)
//        assertTrue(walletMetadata.clientIdSchemesSupported?.contains(ClientIdScheme.REDIRECT_URI) == true)
//    }
//
//    @Test
//    fun `should throw error when construct method is called with null or empty map`() {
//        val ex1 = assertFailsWith<OpenID4VPExceptions.InvalidData> {
//            WalletMetadata.construct(null)
//        }
//        assertEquals("vpSigningAlgorithmSupported should at least have one supported format type", ex1.message)
//
//        val ex2 = assertFailsWith<OpenID4VPExceptions.InvalidData> {
//            WalletMetadata.construct(emptyMap())
//        }
//        assertEquals("vpSigningAlgorithmSupported should at least have one supported format type", ex2.message)
//    }
//
//    @Test
//    fun `should throw error when construct method is called with empty signing algorithms list`() {
//        val ex = assertFailsWith<OpenID4VPExceptions.InvalidData> {
//            WalletMetadata.construct(
//                mapOf(
//                    VPFormatType.LDP_VC to emptyList()
//                )
//            )
//        }
//        assertEquals("Signing Algorithm supported for LDP_VC should not be empty", ex.message)
//    }
//
//    @Test
//    fun `should create VPFormatSupported with null algValuesSupported`() {
//        val vpFormatSupported = VPFormatSupported(null)
//        assertNull(vpFormatSupported.algValuesSupported)
//    }
//
//    @Test
//    fun `should use default values for requestObjectSigningAlgValuesSupported when null`() {
//        val walletMetadata = WalletMetadata(
//            vpFormatsSupported = mapOf(
//                VPFormatType.LDP_VC to VPFormatSupported(
//                    algValuesSupported = listOf("EdDSA")
//                )
//            ),
//            requestObjectSigningAlgValuesSupported = null
//        )
//
//        assertEquals(listOf(RequestSigningAlgorithm.EdDSA), walletMetadata.requestObjectSigningAlgValuesSupported)
//    }
//}
