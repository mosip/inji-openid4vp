package io.mosip.openID4VP.common

import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import io.mosip.openID4VP.encodeToBase64Url

object URDNA2015Canonicalization{
    fun canonicalize(jsonString: String): String{
        val confDocumentLoader: ConfigurableDocumentLoader = getConfigurableDocumentLoader()
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(jsonString)
        vcJsonLdObject.documentLoader = confDocumentLoader
        val ldProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)
        val canonicalizer = URDNA2015Canonicalizer()
        val canonicalHashBytes = canonicalizer.canonicalize(ldProof, vcJsonLdObject)
        return encodeToBase64Url(canonicalHashBytes)
    }

    private fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
        val confDocumentLoader = ConfigurableDocumentLoader()
        confDocumentLoader.isEnableHttps = true
        confDocumentLoader.isEnableHttp = true
        confDocumentLoader.isEnableFile = false
        return confDocumentLoader
    }
}