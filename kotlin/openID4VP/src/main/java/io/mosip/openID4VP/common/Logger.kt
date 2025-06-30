package io.mosip.openID4VP.common

import android.util.Log
import io.mosip.openID4VP.jwt.exception.JWEException
import io.mosip.openID4VP.jwt.exception.JWSException

//TODO: Log - use common logger for android and Java env
object Logger {
    private var traceabilityId: String? = null

    fun setTraceabilityId(traceabilityId: String) {
        this.traceabilityId = traceabilityId
    }

    fun getLogTag(className: String): String {
        return "INJI-OpenID4VP : class name - $className | traceID - ${this.traceabilityId ?: ""}"
    }

    fun error(logTag: String, exception: Exception, className: String? = "") {
        Log.e(logTag, exception.message!!)
    }
}