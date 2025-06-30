package io.mosip.openID4VP.testData

inline fun <T> assertDoesNotThrow(block: () -> T): T {
    return try {
        block()
    } catch (e: Throwable) {
        throw AssertionError("Expected no exception to be thrown, but got: ${e::class.simpleName}", e)
    }
}