package io.mosip.openID4VP.common

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object DateUtil {
    fun formattedCurrentDateTime(): String {
        val formatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        val createdDateAndTime = formatter.format(Date())
        return createdDateAndTime
    }
}