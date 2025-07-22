package io.mosip.sampleapp.utils

import android.util.Log
import androidx.compose.runtime.snapshots.SnapshotStateList
import com.nimbusds.jose.jwk.OctetKeyPair
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.DeviceAuthentication
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.sampleapp.data.HardcodedOVPData.getListOfVerifiers
import io.mosip.sampleapp.data.HardcodedOVPData.getWalletMetadata
import io.mosip.sampleapp.data.VCMetadata
import io.mosip.sampleapp.utils.SampleKeyGenerator.SIGNATURE_SUITE
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.KeyPair

object OpenID4VPManager {
    private var _instance: OpenID4VP? = null
    val instance: OpenID4VP
        get() = _instance ?: throw IllegalStateException("OpenID4VP is not initialized")

    fun init(traceabilityId: String) {
        _instance = OpenID4VP(traceabilityId, getWalletMetadata())
    }

    fun authenticateVerifier(
        urlEncodedAuthRequest: String
    ): AuthorizationRequest {
        return try {
            instance.authenticateVerifier(
                urlEncodedAuthorizationRequest = urlEncodedAuthRequest,
                trustedVerifiers = getListOfVerifiers(),
                shouldValidateClient = false
            )
        } catch (exception: Exception) {
            Log.e("OpenID4VP-sample wallet", "Error authenticating verifier ${exception.message}")
            throw exception
        }
    }

    private fun constructUnsignedVpToken(selectedCredentials : Map<String, Map<FormatType, List<Any>>>, holderId: String, signatureSuite: String): Map<FormatType, UnsignedVPToken> {
        return try {
            instance.constructUnsignedVPToken(selectedCredentials, holderId, signatureSuite)
        } catch (exception: Exception) {
            Log.e("OpenID4VP-sample wallet", "Error constructing Unsigned vp token: ${exception.message}")
            throw exception
        }
    }

    fun shareVerifiablePresentation(selectedItems: SnapshotStateList<Pair<String, VCMetadata>>) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                sendVP(selectedItems)
            } catch (exception: Exception) {
                Log.e("OpenID4VP-sample wallet", "Error sharing Verifiable Presentation: ${exception.message}")
                throw exception
            }
        }
    }


    private suspend fun sendVP(selectedItems: SnapshotStateList<Pair<String, VCMetadata>>) = withContext(
        Dispatchers.IO) {
        val parsedSelectedItems = MatchingVcsHelper().buildSelectedVCsMapPlain(selectedItems)


        // LDP_VC signing
        val ldpKeyType = KeyType.Ed25519
        val ldpKeyPair = SampleKeyGenerator.generateKeyPair(ldpKeyType)
        val holderId = DetachedJwtKeyManager.generateHolderId(ldpKeyPair as OctetKeyPair)

        val unsignedVpTokenMap = constructUnsignedVpToken(parsedSelectedItems,
            holderId, SIGNATURE_SUITE)


        val ldpSigningResult = unsignedVpTokenMap[FormatType.LDP_VC]?.let { vpPayload ->


            val result = VPTokenSigner.signVpToken(ldpKeyType, (vpPayload as UnsignedLdpVPToken).dataToSign, ldpKeyPair)

            LdpVPTokenSigningResult(
                jws = result.jws,
                signatureAlgorithm = result.signatureAlgorithm
            )
        }

        // MSO_MDOC signing
        val mdocKeyType = KeyType.ES256
        val mdocKeyPair = SampleKeyGenerator.generateKeyPair(mdocKeyType)

        val mdocSigningResult = unsignedVpTokenMap[FormatType.MSO_MDOC]?.let { payload ->
            val mdocPayload = payload as UnsignedMdocVPToken
            val docTypeToDeviceAuthenticationBytes = mdocPayload.docTypeToDeviceAuthenticationBytes

            val docTypeToDeviceAuthentication = docTypeToDeviceAuthenticationBytes.mapValues { (_, deviceAuthBytes) ->
                val bytes = if (deviceAuthBytes is String) {
                    deviceAuthBytes.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                } else deviceAuthBytes as ByteArray
                val signed = VPTokenSigner.signDeviceAuthentication(mdocKeyPair as KeyPair, mdocKeyType, bytes)
                val jwsParts = signed.jws.split(".")
                val signaturePart = if (jwsParts.size == 3) jwsParts[2] else signed.jws
                DeviceAuthentication(signature = signaturePart, algorithm = signed.signatureAlgorithm)
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

    fun sendErrorToVerifier(ovpException: OpenID4VPExceptions) {
        return instance.sendErrorToVerifier(ovpException)
    }
}

