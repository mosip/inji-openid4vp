package io.mosip.openID4VP.common

import android.annotation.SuppressLint
import android.os.Build
import android.util.Base64
import io.mosip.vercred.vcverifier.utils.BuildConfig.getVersionSDKInt

actual fun decodeBase64Data(content: String): ByteArray {
    val decodedBase64ByteArray =
        if( getVersionSDKInt() >= Build.VERSION_CODES.O){
            javaBase64UrlDecode(content)
        } else {
            androidBase64UrlDecode(content)
        }
    return decodedBase64ByteArray
}

@SuppressLint("NewApi")
private fun javaBase64UrlDecode(content: String): ByteArray =
    java.util.Base64.getUrlDecoder().decode(content.toByteArray())

private fun androidBase64UrlDecode(content: String): ByteArray {
    return Base64.decode(content, Base64.DEFAULT or Base64.URL_SAFE)
}