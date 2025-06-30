package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import kotlin.test.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

class WalletMetadataTest {


    @Test
    fun `should take default value for presentation_definition_uri_supported if it is null`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = null,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = listOf(
                ClientIdScheme.REDIRECT_URI.value,
                PRE_REGISTERED.value
            ),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        assertEquals(true, walletMetadata.presentationDefinitionURISupported)
    }

    @Test
    fun `should take default value for client_id_schemes_supported if it is null`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = null,
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        assertEquals(listOf(PRE_REGISTERED.value), walletMetadata.clientIdSchemesSupported)
    }

    @Test
    fun `should keep null values for encryption alg and enc if provided`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = null,
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = null
        )
        assertEquals(listOf(PRE_REGISTERED.value), walletMetadata.clientIdSchemesSupported)
        assertNull(walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertNull(walletMetadata.authorizationEncryptionEncValuesSupported)
    }

    @Test
    fun `should throw error if vp_formats_supported is empty map`() {
        val ex = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                presentationDefinitionURISupported = true,
                vpFormatsSupported = emptyMap(),
                clientIdSchemesSupported = listOf(
                    ClientIdScheme.REDIRECT_URI.value,
                    PRE_REGISTERED.value
                ),
                requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
                authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
                authorizationEncryptionEncValuesSupported = listOf("A256GCM")
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, ex.errorCode)
        assertEquals(
            "vp_formats_supported should at least have one supported vp_format",
            ex.message
        )
    }

    @Test
    fun `should throw error if vp_formats_supported has empty key`() {
        val ex = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                presentationDefinitionURISupported = true,
                vpFormatsSupported = mapOf(
                    "" to VPFormatSupported(
                        algValuesSupported = null
                    )
                ),
                clientIdSchemesSupported = listOf(
                    ClientIdScheme.REDIRECT_URI.value,
                    PRE_REGISTERED.value
                ),
                requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
                authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
                authorizationEncryptionEncValuesSupported = listOf("A256GCM")
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, ex.errorCode)
        assertEquals(
            "vp_formats_supported cannot have empty keys",
            ex.message
        )
    }

    @Test
    fun `should throw error if vp_formats_supported has just empty space`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                presentationDefinitionURISupported = true,
                vpFormatsSupported = mapOf(
                    " " to VPFormatSupported(
                        algValuesSupported = null
                    )
                ),
                clientIdSchemesSupported = listOf(
                    ClientIdScheme.REDIRECT_URI.value,
                    PRE_REGISTERED.value
                ),
                requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
                authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
                authorizationEncryptionEncValuesSupported = listOf("A256GCM")
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals(
            "vp_formats_supported cannot have empty keys",
            exception.message
        )
    }
}
