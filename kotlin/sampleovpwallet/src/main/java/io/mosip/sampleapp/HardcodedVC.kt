package io.mosip.sampleapp

import com.google.gson.Gson
import com.google.gson.JsonObject
import io.mosip.openID4VP.constants.FormatType
import io.mosip.pixelpass.PixelPass
import io.mosip.sampleapp.utils.KeyType
import io.mosip.sampleapp.utils.MdocKeyManager
import org.json.JSONObject

object HardcodedVC {
    const val MOSIP_VC = """
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1/mosip",
        "https://schema.org/"
    ],
    "credentialSubject": {
        "gender": [
            {
                "language": "eng",
                "value": "Male"
            },
            {
                "language": "fra",
                "value": "Mâle"
            },
            {
                "language": "ara",
                "value": "ذكر"
            }
        ],
        "postalCode": "45009",
        "fullName": [
            {
                "language": "fra",
                "value": "Siddharth K Mansour"
            },
            {
                "language": "ara",
                "value": "تتگلدكنسَزقهِقِفل دسييسيكدكنوڤو"
            },
            {
                "language": "eng",
                "value": "Siddharth K Mansour"
            }
        ],
        "dateOfBirth": "1987/11/25",
        "face": "sqauare logo",
        "province": [
            {
                "language": "fra",
                "value": "yuān 2"
            },
            {
                "language": "ara",
                "value": "يَُانꉛ⥍"
            },
            {
                "language": "eng",
                "value": "yuan wee"
            }
        ],
        "phone": "+919427357934",
        "addressLine1": [
            {
                "language": "fra",
                "value": "yuān⥍"
            },
            {
                "language": "ara",
                "value": ""
            },
            {
                "language": "eng",
                "value": "Slung"
            }
        ],
        "vcVer": "VC-V1",
        "id": "https://api.dev1.mosip.net/v1/mock-identity-system/identity/1234567",
        "UIN": "1234567",
        "region": [
            {
                "language": "fra",
                "value": "yuān 3"
            },
            {
                "language": "ara",
                "value": ""
            },
            {
                "language": "eng",
                "value": "yuan wee 3"
            }
        ],
        "email": "siddhartha.km@gmail.com"
    },
    "id": "did:uuid:1d93e315-d979-480b-a7a2-a0ff01f1856f",
    "issuanceDate": "2024-11-06T10:44:19.044Z",
    "issuer": "did:example:123456789",
    "proof": {
        "created": "2024-11-06T10:44:19Z",
        "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJraWQiOiJLYlJXRU9YQ0pVRENWVnVET2ZsSkRQWnAtXzNqMEZvajd1RVZHd19xOEdzIiwiYWxnIjoiUFMyNTYifQ..NEcXf5IuDf0eJcBbtIBsXC2bZeOzNBduWG7Vz9A3ePcvh-SuwggPcCPQLrdgl79ta5bYsKsJSKVSS0Xg-GvlY71I2OzU778Bkq52LIDtSXY3DrxQEvM-BqjKLBB-ScA850pG2gV-k_8nkCPmAdvda_jj2Vlkss7VPB5LI6skWTgM4MOyvlMzZCzqmifqTzHLVgefzfixld7E38X7wxzEZfn2lY_fRfWqcL8pKL_kijTHwdTWLb9hMQtP9vlk2iarbT8TmZqutZD8etd1PBFm7V_izcY9cO75A4N3fVrr6NC50cDHDshPZFS48uTBDK-SSePxibpmq1afaS_VX6kX7A",
        "proofPurpose": "assertionMethod",
        "type": "RsaSignature2018",
        "verificationMethod": "https://api.dev1.mosip.net/.well-known/ida-public-key.json"
    },
    "type": [
        "VerifiableCredential",
        "MosipVerifiableCredential"
    ]
}
    """

    const val INSURANCE_VC = """
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1/insurance",
        "https://schema.org/"
    ],
    "credentialSubject": {
        "gender": [
            {
                "language": "eng",
                "value": "Male"
            },
            {
                "language": "fra",
                "value": "Mâle"
            },
            {
                "language": "ara",
                "value": "ذكر"
            }
        ],
        "postalCode": "45009",
        "fullName": [
            {
                "language": "fra",
                "value": "Siddharth K Mansour"
            },
            {
                "language": "ara",
                "value": "تتگلدكنسَزقهِقِفل دسييسيكدكنوڤو"
            },
            {
                "language": "eng",
                "value": "Siddharth K Mansour"
            }
        ],
        "dateOfBirth": "1987/11/25",
        "face": "sqauare logo",
        "province": [
            {
                "language": "fra",
                "value": "yuān 2"
            },
            {
                "language": "ara",
                "value": "يَُانꉛ⥍"
            },
            {
                "language": "eng",
                "value": "yuan wee"
            }
        ],
        "phone": "+919427357934",
        "addressLine1": [
            {
                "language": "fra",
                "value": "yuān⥍"
            },
            {
                "language": "ara",
                "value": ""
            },
            {
                "language": "eng",
                "value": "Slung"
            }
        ],
        "vcVer": "VC-V1",
        "id": "https://api.dev1.mosip.net/v1/mock-identity-system/identity/1234567",
        "UIN": "1234567",
        "region": [
            {
                "language": "fra",
                "value": "yuān 3"
            },
            {
                "language": "ara",
                "value": ""
            },
            {
                "language": "eng",
                "value": "yuan wee 3"
            }
        ],
        "email": "siddhartha.km@gmail.com"
    },
    "id": "did:uuid:1d93e315-d979-480b-a7a2-a0ff01f1856f",
    "issuanceDate": "2024-11-06T10:44:19.044Z",
    "issuer": "did:example:123456789",
    "proof": {
        "created": "2024-11-06T10:44:19Z",
        "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJraWQiOiJLYlJXRU9YQ0pVRENWVnVET2ZsSkRQWnAtXzNqMEZvajd1RVZHd19xOEdzIiwiYWxnIjoiUFMyNTYifQ..NEcXf5IuDf0eJcBbtIBsXC2bZeOzNBduWG7Vz9A3ePcvh-SuwggPcCPQLrdgl79ta5bYsKsJSKVSS0Xg-GvlY71I2OzU778Bkq52LIDtSXY3DrxQEvM-BqjKLBB-ScA850pG2gV-k_8nkCPmAdvda_jj2Vlkss7VPB5LI6skWTgM4MOyvlMzZCzqmifqTzHLVgefzfixld7E38X7wxzEZfn2lY_fRfWqcL8pKL_kijTHwdTWLb9hMQtP9vlk2iarbT8TmZqutZD8etd1PBFm7V_izcY9cO75A4N3fVrr6NC50cDHDshPZFS48uTBDK-SSePxibpmq1afaS_VX6kX7A",
        "proofPurpose": "assertionMethod",
        "type": "RsaSignature2018",
        "verificationMethod": "https://api.dev1.mosip.net/.well-known/ida-public-key.json"
    },
    "type": [
        "VerifiableCredential",
        "InsuranceVerifiableCredential"
    ]
}
    """

    const val MOCK_VC = """
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1/mock",
        "https://schema.org/"
    ],
    "credentialSubject": {
        "gender": [
            {
                "language": "eng",
                "value": "Male"
            },
            {
                "language": "fra",
                "value": "Mâle"
            },
            {
                "language": "ara",
                "value": "ذكر"
            }
        ],
        "postalCode": "45009",
        "fullName": [
            {
                "language": "fra",
                "value": "Siddharth K Mansour"
            },
            {
                "language": "ara",
                "value": "تتگلدكنسَزقهِقِفل دسييسيكدكنوڤو"
            },
            {
                "language": "eng",
                "value": "Siddharth K Mansour"
            }
        ],
        "dateOfBirth": "1987/11/25",
        "face": "sqauare logo",
        "province": [
            {
                "language": "fra",
                "value": "yuān 2"
            },
            {
                "language": "ara",
                "value": "يَُانꉛ⥍"
            },
            {
                "language": "eng",
                "value": "yuan wee"
            }
        ],
        "phone": "+919427357934",
        "addressLine1": [
            {
                "language": "fra",
                "value": "yuān⥍"
            },
            {
                "language": "ara",
                "value": ""
            },
            {
                "language": "eng",
                "value": "Slung"
            }
        ],
        "vcVer": "VC-V1",
        "id": "https://api.dev1.mosip.net/v1/mock-identity-system/identity/1234567",
        "UIN": "1234567",
        "region": [
            {
                "language": "fra",
                "value": "yuān 3"
            },
            {
                "language": "ara",
                "value": ""
            },
            {
                "language": "eng",
                "value": "yuan wee 3"
            }
        ],
        "email": "siddhartha.km@gmail.com"
    },
    "id": "did:uuid:1d93e315-d979-480b-a7a2-a0ff01f1856f",
    "issuanceDate": "2024-11-06T10:44:19.044Z",
    "issuer": "did:example:123456789",
    "proof": {
        "created": "2024-11-06T10:44:19Z",
        "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJraWQiOiJLYlJXRU9YQ0pVRENWVnVET2ZsSkRQWnAtXzNqMEZvajd1RVZHd19xOEdzIiwiYWxnIjoiUFMyNTYifQ..NEcXf5IuDf0eJcBbtIBsXC2bZeOzNBduWG7Vz9A3ePcvh-SuwggPcCPQLrdgl79ta5bYsKsJSKVSS0Xg-GvlY71I2OzU778Bkq52LIDtSXY3DrxQEvM-BqjKLBB-ScA850pG2gV-k_8nkCPmAdvda_jj2Vlkss7VPB5LI6skWTgM4MOyvlMzZCzqmifqTzHLVgefzfixld7E38X7wxzEZfn2lY_fRfWqcL8pKL_kijTHwdTWLb9hMQtP9vlk2iarbT8TmZqutZD8etd1PBFm7V_izcY9cO75A4N3fVrr6NC50cDHDshPZFS48uTBDK-SSePxibpmq1afaS_VX6kX7A",
        "proofPurpose": "assertionMethod",
        "type": "RsaSignature2018",
        "verificationMethod": "https://api.dev1.mosip.net/.well-known/ida-public-key.json"
    },
    "type": [
        "VerifiableCredential",
        "MockVerifiableCredential"
    ]
}
    """

    const val MDOC_CBOR_DATA = "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkCADCCAfwwggGjAhQF2zbegdWq1XHLmdrVZZIORS_efDAKBggqhkjOPQQDAjCBgDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoMBUlJSVRCMQwwCgYDVQQLDANEQ1MxEDAOBgNVBAMMB0NFUlRJRlkxIDAeBgkqhkiG9w0BCQEWEW1vc2lwcWFAZ21haWwuY29tMB4XDTI1MDIxMjEyMzE1N1oXDTI2MDIxMjEyMzE1N1owgYAxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEMMAoGA1UECwwDRENTMRAwDgYDVQQDDAdDRVJUSUZZMSAwHgYJKoZIhvcNAQkBFhFtb3NpcHFhQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAcZXrsgNSABzg9o_dNKu6S2pXuJ3hgYlX162Ex56IUGDJZP_IlRCrEQPHZSSl53DwlpL4iHisASqFaRQiXAtqkwCgYIKoZIzj0EAwIDRwAwRAIgGI6B63QccJQ4B84hRjRGlRURJ5SSNTuf74w-nE8zqRACIA3diiD3VCA5G6joGeTSX-Xx79shhDrCmUHuj3Lk5uL1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggOtUinSp1p72_x8vjovozcBMpag6gpWu8iudwS4Ek1ZMGWCDNK9J0AS42E9TO7bvQh_e5iaObQIJi9gO65LO_1vut4wNYIIkTrsz3KrQLn6bEi7GPXub3DEhGdzTOQDUTV5IwLFMsAVgg7yKtNJ8lgUdh146aKVbwSEnZM6e6gBc5yv8lqvkiIbAEWCBeZlkW29iqUBLxAFlOfHrz5qXioXKKaoyEEYI96YyKvwBYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIJjKhVKuqedRCOVd9NiyrOeA7kxOeLdxSo8Xg3_RRQamIlggIzQbUfegKbBtwFYH6UKwjJQGDyvaY7swgKySjIyRmYlsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjUtMDYtMDZUMDk6NDM6MDJaaXZhbGlkRnJvbcB0MjAyNS0wNi0wNlQwOTo0MzowMlpqdmFsaWRVbnRpbMB0MjAyNy0wNi0wNlQwOTo0MzowMlpYQLYS8sv9ZlvCNIRldg_BPG5z6p6pQ4I0KSAoSdl-u2YZIruwVWT7c10D64Ybb334u0D9pjZigObV69BbTScLOalqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjUtMDYtMDbYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMzAtMDYtMDbYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNS0wNi0wNiwgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMzAtMDYtMDZ92BhYaaRoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWV2SFFObS1tYW5Nam1FSTJFWjdVMG1rUdgYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYklO2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE="

    fun get(index: Int): VCMetadata {
        val gson = Gson()
        return when (index) {
            0 -> VCMetadata(FormatType.LDP_VC.value, gson.fromJson(MOSIP_VC, JsonObject::class.java), KeyType.RSA.name)
            1 -> VCMetadata(FormatType.LDP_VC.value, gson.fromJson(INSURANCE_VC, JsonObject::class.java), KeyType.RSA.name)
            2 -> VCMetadata(FormatType.LDP_VC.value, gson.fromJson(MOCK_VC, JsonObject::class.java), KeyType.RSA.name)
            else -> {
                val rawMdoc = PixelPass().toJson(MDOC_CBOR_DATA)
                val jsonString = when (rawMdoc) {
                    is JSONObject -> rawMdoc.toString()
                    is String -> rawMdoc
                    else -> gson.toJson(rawMdoc)
                }
                val mdocJsonObject = gson.fromJson(jsonString, JsonObject::class.java)
                val mdocKeyType = getKeyTypeForMdoc(mdocJsonObject)

                VCMetadata(FormatType.MSO_MDOC.value, mdocJsonObject, mdocKeyType, MDOC_CBOR_DATA)
            }
        }
    }
}

fun getKeyTypeForMdoc(vc: JsonObject): String {
    val issuerAuthArray = vc.getAsJsonObject("issuerSigned")
        ?.getAsJsonArray("issuerAuth") ?: return ""

    if (issuerAuthArray.size() < 3) return ""

    val mdocAuth = issuerAuthArray[2].asJsonObject
    return MdocKeyManager.getMdocAuthenticationAlgorithm(mdocAuth)
}



data class VCMetadata(
    val format: String,
    val vc: JsonObject,
    val keyType: String,
    val rawCBORData : String? = null
)
