package io.mosip.openID4VP.authorizationRequest

enum class AuthorizationRequestFieldConstants(val value: String) {
    CLIENT_ID ("client_id"),
    CLIENT_ID_SCHEME ("client_id_scheme"),
    RESPONSE_TYPE ("response_type"),
    RESPONSE_MODE ("response_mode"),
    PRESENTATION_DEFINITION ("presentation_definition"),
    PRESENTATION_DEFINITION_URI ("presentation_definition_uri"),
    RESPONSE_URI ("response_uri"),
    REDIRECT_URI ("redirect_uri"),
    REQUEST_URI ("request_uri"),
    REQUEST_URI_METHOD ("request_uri_method"),
    NONCE ("nonce"),
    STATE ("state"),
    CLIENT_METADATA ("client_metadata")
}
