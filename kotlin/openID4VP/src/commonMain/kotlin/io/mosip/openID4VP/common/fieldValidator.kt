package io.mosip.openID4VP.common

fun validateField(field: Any?, fieldType: String?): Boolean {
	var res = true
	when {
		fieldType == "String" -> res = field.toString().isNotEmpty()

		fieldType?.startsWith("List") == true -> res = (field as? List<*>)?.isNotEmpty() ?: false

		fieldType == "Boolean" -> res = (field == true || field == false)
	}
	return res
}