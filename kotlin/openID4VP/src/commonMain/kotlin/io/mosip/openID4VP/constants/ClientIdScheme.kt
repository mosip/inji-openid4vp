package io.mosip.openID4VP.constants

enum class ClientIdScheme(val value: String) {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    DID("did")
}

