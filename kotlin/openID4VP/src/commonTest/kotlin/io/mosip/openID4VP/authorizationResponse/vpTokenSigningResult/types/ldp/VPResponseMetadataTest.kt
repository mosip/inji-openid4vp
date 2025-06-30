package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import kotlin.test.*

class VPResponseMetadataTest {

    @BeforeTest
    fun setUp() {
        mockkStatic(::validateField)

        every { validateField(any(), "String") } answers {
            val value = arg<String?>(0)
            value != null && value.isNotEmpty()
        }

//        every {
//            Logger.handleException(any(), any(), any(), any())
//        } returns InvalidInput("", "Validation failed")
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should create valid instance with all valid fields`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        metadata.validate()
    }

    @Test
    fun `should throw exception when jws is empty`() {
        val metadata = VPResponseMetadata(
            jws = "",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        assertFailsWith<InvalidInput> {
            metadata.validate()
        }
    }

    @Test
    fun `should throw exception when jws is null string`() {
        val metadata = VPResponseMetadata(
            jws = "null",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        assertFailsWith<InvalidInput> {
            metadata.validate()
        }
    }

    @Test
    fun `should throw exception when signatureAlgorithm is empty`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        assertFailsWith<InvalidInput> {
            metadata.validate()
        }
    }

    @Test
    fun `should throw exception when signatureAlgorithm is null string`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "null",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        assertFailsWith<InvalidInput> {
            metadata.validate()
        }
    }

    @Test
    fun `should throw exception when publicKey is empty`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "",
            domain = "example.com"
        )

        assertFailsWith<InvalidInput> {
            metadata.validate()
        }
    }

    @Test
    fun `should throw exception when publicKey is null string`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "null",
            domain = "example.com"
        )

        assertFailsWith<InvalidInput> {
            metadata.validate()
        }
    }

    @Test
    fun `should throw exception when domain is empty`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = ""
        )

        assertFailsWith<InvalidInput> {
            metadata.validate()
        }
    }

    @Test
    fun `should throw exception when domain is null string`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = "null"
        )

        assertFailsWith<InvalidInput> {
            metadata.validate()
        }
    }
}
