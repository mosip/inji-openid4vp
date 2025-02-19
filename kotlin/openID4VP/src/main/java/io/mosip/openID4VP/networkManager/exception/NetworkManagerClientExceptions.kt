package io.mosip.openID4VP.networkManager.exception

sealed class NetworkManagerClientExceptions {
    class NetworkRequestTimeout :
        Exception("VP sharing failed due to connection timeout")

    class NetworkRequestFailed(error: String) :
        Exception("Network request failed with error response - $error")

    class UrlValidationFailed(error: String) :
        Exception("Network request failed with error response - $error")


}