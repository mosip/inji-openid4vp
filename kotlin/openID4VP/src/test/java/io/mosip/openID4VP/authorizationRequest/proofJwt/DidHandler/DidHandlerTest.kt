package io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.jupiter.api.assertDoesNotThrow

class DidHandlerTest {
//    @Test
//    fun `should verify the valid JWT with public key in did successfully`() {
//        val jwt =
//            "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoieWtCb2ZxVFBvQkMvby9iWHZjaXFkQT09Iiwibm9uY2UiOiJCaUxzM093QTZ4bU5uYzZSa204ZjZnPT0iLCJjbGllbnRfaWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ZwLXJlc3BvbnNlIn0.374Bhb1yU1BM3BLLj5NvI27nPx8DLqSDk669-Hil2XEySk4JhTNYpEt8F1p0_YxWsPy4RSXIaZDN_90LOWz9AQ"
//        val clientId = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
//
//        assertDoesNotThrow { DidHandler().verify(jwt, clientId) }
//    }
//
//    @Test
//    fun `should throw exception when JWT signature verification fails`() {
//        val jwtWithInvalidSignature =
//            "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoieWtCb2ZxVFBvQkMvby9iWHZjaXFkQT09Iiwibm9uY2UiOiJCaUxzM093QTZ4bU5uYzZSa204ZjZnPT0iLCJjbGllbnRfaWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ZwLXJlc3BvbnNlIn0.374Bhb1yU1BM3BLLj5NvI27nPx8DLqSDk669-Hil2XEySk4JhTNYpEt8F1p0_YxWsPy4RSXIaZDN_de3r90LOWz9AQ"
//        val clientId = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
//
//
//        val exception: Exception = assertThrows(JWTVerificationException.InvalidSignature::class.java) {
//            DidHandler().verify(jwtWithInvalidSignature, clientId)
//        }
//
//        assertEquals("JWT signature verification failed (className=DidHandler)",exception.message)
//    }
//
//    @Test
//    fun `should thrown invalid jwt exception when JWT is invalid`() {
//        val jwtWithoutSignature =
//            "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoieWtCb2ZxVFBvQkMvby9iWHZjaXFkQT09Iiwibm9uY2UiOiJCaUxzM093QTZ4bU5uYzZSa204ZjZnPT0iLCJjbGllbnRfaWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ZwLXJlc3BvbnNlIn0.374Bhb1yU1BM3BLLj5NvI27nPx8DLqSDk669-Hil2XEySk4JhTNYpEt8F1p0_YxWsPy4RSXIaZDN_90LOWz9AQ.fgeim==="
//        val clientId = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
//
//
//        val exception: Exception = assertThrows(JWTVerificationException.InvalidJWT::class.java) {
//            DidHandler().verify(jwtWithoutSignature, clientId)
//        }
//
//        assertEquals("Invalid JWT format",exception.message)
//    }
//
//    @Test
//    fun `should throw Key ID not found exception when Key ID is not available in JWT header`() {
//        val jwtWithoutKeyId = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzAxMjAwMDAwfQ.GM8hTzv8-5xTxzGdHo5opFzU1hR2MnNL9jzCq17vn7FZPEZYIXyo6q6T9EPRLrw6cU_m-ziBoi3EXi0WW"
//        val clientId = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
//
//        val exception: Exception = assertThrows(JWTVerificationException.KidExtractionFailed::class.java) {
//            DidHandler().verify(jwtWithoutKeyId, clientId)
//        }
//
//        assertEquals("KidExtractionFailed: KID extraction from DID document failed (className=DidHandler)",exception.message)
//    }
//
//    @Test
//    fun `should throw publicKey extraction failure exception when public key is not extractable`() {
//        val jwtNonExtractablePublicKey = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMzQ1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzAxMjAwMDAwfQ.qD9hT4YF7i0tN4oP6ZQvcxJcbzV3J-m2C6GlXnZDWUVF2WvuAOPLMyU7wxlBCTsgJzR8GSKjDO6l9GrLDBSFCg"
//        val clientId = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
//
//        val exception: Exception = assertThrows(JWTVerificationException.PublicKeyExtractionFailed::class.java) {
//            DidHandler().verify(jwtNonExtractablePublicKey, clientId)
//        }
//
//        assertEquals("PublicKeyExtractionFailed: Public key extraction failed (className=DidHandler)",exception.message)
//    }
}