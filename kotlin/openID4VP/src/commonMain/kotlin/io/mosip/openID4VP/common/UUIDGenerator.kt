package io.mosip.openID4VP.common

import java.util.UUID

object UUIDGenerator {
    fun generateUUID(): String {
        return "urn:uuid:${UUID.randomUUID()}"
    }
}
