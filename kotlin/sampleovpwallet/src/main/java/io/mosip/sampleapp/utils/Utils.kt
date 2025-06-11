package io.mosip.sampleapp.utils

import io.mosip.openID4VP.constants.FormatType
import io.mosip.sampleapp.VCMetadata

object Utils {
    fun getDisplayLabel(vcMetadata: VCMetadata): String? {
        val typeLabel = when (vcMetadata.format) {
            FormatType.LDP_VC.value -> {
                val typeArray = vcMetadata.vc.getAsJsonArray("type")
                if (typeArray != null && typeArray.size() > 1) {
                    typeArray[1].asString
                } else {
                    "-"
                }
            }

            FormatType.MSO_MDOC.value -> {
                "MDL Driving License"
            }

            else -> "-"
        }
        return typeLabel
    }
}