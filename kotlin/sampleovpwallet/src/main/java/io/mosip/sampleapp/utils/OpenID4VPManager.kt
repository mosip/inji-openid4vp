package io.mosip.sampleapp.utils

import android.util.Log
import androidx.compose.runtime.snapshots.SnapshotStateList
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.reflect.TypeToken
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.sampleapp.VCMetadata
import io.mosip.sampleapp.utils.AuthenticateVerifierHelper.extractWalletMetadata
import io.mosip.sampleapp.utils.AuthenticateVerifierHelper.isClientValidationRequired
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

object OpenID4VPManager {
    private var _instance: OpenID4VP? = null
    val instance: OpenID4VP
        get() = _instance ?: throw IllegalStateException("OpenID4VP is not initialized")

    fun init(traceabilityId: String) {
        _instance = OpenID4VP(traceabilityId)
    }

    fun authenticateVerifier(
        urlEncodedAuthRequest: String,
        trustedVerifiers: List<Verifier>,
        allProperties: JsonObject?
    ): AuthorizationRequest {

        val walletMetadata = extractWalletMetadata(allProperties)
        val validateClient = isClientValidationRequired(allProperties)

        return instance.authenticateVerifier(
            urlEncodedAuthorizationRequest = urlEncodedAuthRequest,
            trustedVerifiers = trustedVerifiers,
            walletMetadata = walletMetadata,
            shouldValidateClient = validateClient
        )
    }

    fun constructUnsignedVpToken(selectedCredentials : Map<String, Map<FormatType, List<String>>>): Map<FormatType, UnsignedVPToken> {
        return instance.constructUnsignedVPToken(selectedCredentials)
    }

    fun shareVerifiablePresentation(selectedItems: SnapshotStateList<Pair<String, VCMetadata>>) {
        CoroutineScope(Dispatchers.IO).launch {
            sendVP(selectedItems)
        }
    }


    suspend fun sendVP(selectedItems: SnapshotStateList<Pair<String, VCMetadata>>) = withContext(
        Dispatchers.IO) {
        val parsedSelectedItems = MatchingVcsHelper().buildSelectedVCsMapPlain(selectedItems)

        val unsignedVpTokenMap = constructUnsignedVpToken(parsedSelectedItems)

        // LDP_VC signing
        val ldpSigningResult = run {
            val vpPayload = unsignedVpTokenMap[FormatType.LDP_VC] ?: return@run null
            val gson = Gson()
            val jsonElement = gson.toJsonTree(vpPayload)
            val mapPayload: Map<String, Any> = gson.fromJson(jsonElement, object : TypeToken<Map<String, Any>>() {}.type)
            val keyType = KeyType.RSA
            val keyPair = VPTokenSigner.generateKeyPair(keyType)
            val result: SignedVPJWT = VPTokenSigner.signVPToken(keyPair, keyType, mapPayload)
            LdpVPTokenSigningResult(
                jws = result.jwt,
                signatureAlgorithm = result.algorithm,
                publicKey = result.publicJWK,
                domain = "OpenID4VP"
            )
        }

        // MSO_MDOC signing
        val mdocSigningResult = run {
            val mdocPayload = unsignedVpTokenMap[FormatType.MSO_MDOC] as UnsignedMdocVPToken
            val docTypeToDeviceAuthenticationBytes = mdocPayload.docTypeToDeviceAuthenticationBytes
            val keyType = KeyType.ES256
            val keyPair = VPTokenSigner.generateKeyPair(keyType)
            val docTypeToDeviceAuthentication = docTypeToDeviceAuthenticationBytes.mapValues { (_, deviceAuthBytes) ->
                val bytes = if (deviceAuthBytes is String) {
                    deviceAuthBytes.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                } else deviceAuthBytes as ByteArray
                val signed = VPTokenSigner.signDeviceAuthentication(keyPair, keyType, bytes)
                val jwsParts = signed.jwt.split(".")
                val signaturePart = if (jwsParts.size == 3) jwsParts[2] else signed.jwt
                DeviceAuthentication(signature = signaturePart, algorithm = signed.algorithm)
            }
            MdocVPTokenSigningResult(docTypeToDeviceAuthentication)
        }

        val vpTokenSigningResultMap = buildMap {
            ldpSigningResult?.let { put(FormatType.LDP_VC, it) }
            mdocSigningResult?.let { put(FormatType.MSO_MDOC, it) }
        }

        try {
            val finalResponse = instance.shareVerifiablePresentation(vpTokenSigningResultMap)
            Log.d("VP_SHARE", "######## $finalResponse")
        } catch (e: Exception) {
            Log.e("VP_SHARE", "Error sharing VP", e)
        }
    }

    fun sendErrorToVerifier(errorMessage: String) {
        return instance.sendErrorToVerifier(Exception(errorMessage))
    }
}

