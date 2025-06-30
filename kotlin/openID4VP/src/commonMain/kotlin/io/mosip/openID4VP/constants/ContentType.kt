package io.mosip.openID4VP.constants

enum class ContentType(val value: String) {
	APPLICATION_JSON("application/json"),
	APPLICATION_JWT("application/oauth-authz-req+jwt"),
	APPLICATION_FORM_URL_ENCODED("application/x-www-form-urlencoded")
}