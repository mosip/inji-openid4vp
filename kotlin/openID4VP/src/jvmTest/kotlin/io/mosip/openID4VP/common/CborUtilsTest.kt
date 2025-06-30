package io.mosip.openID4VP.common

import kotlin.test.Test
import kotlin.test.assertFailsWith


class CborUtilsJvmTest {
    @Test
    fun `determineHttpMethod should throw exception for unsupported method`() {
        assertFailsWith<IllegalArgumentException> {
            determineHttpMethod("put")
        }
    }
}
