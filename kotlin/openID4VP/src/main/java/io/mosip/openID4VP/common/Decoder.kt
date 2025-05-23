package io.mosip.openID4VP.common

import android.annotation.SuppressLint
import android.os.Build
import io.mosip.openID4VP.common.BuildConfig.getVersionSDKInt
import io.mosip.openID4VP.common.BuildConfig.isAndroid

object Decoder {

    fun decodeBase64Data(content: String): ByteArray {
        val decodedBase64ByteArray =  if (isAndroid()) {
            if( getVersionSDKInt() >= Build.VERSION_CODES.O){
                javaBase64UrlDecode(content)
            } else {
                androidBase64UrlDecode(content)
            }
        } else {
            javaBase64UrlDecode(content)
        }
        return decodedBase64ByteArray
    }

    @SuppressLint("NewApi")
    private fun javaBase64UrlDecode(content: String): ByteArray =
        java.util.Base64.getUrlDecoder().decode(content.toByteArray())

    private fun androidBase64UrlDecode(content: String): ByteArray {
        var base64: String = content.replace('-', '+').replace('_', '/')
        when (base64.length % 4) {
            2 -> base64 += "=="
            3 -> base64 += "="
            else -> {}
        }

        return android.util.Base64.decode(base64, android.util.Base64.DEFAULT)
    }
}