package com.yo1000.keycloak.authenticator.verifynewbrowser

import com.fasterxml.jackson.core.type.TypeReference
import org.junit.jupiter.api.Test
import org.keycloak.util.JsonSerialization

class VerifyNewBrowserCredentialModelTest {
    class SecretDataTest {
        @Test
        fun testSerde() {
            val json: String = """{
              "browsers" : [{
                "id" : {
                  "value" : "ozDPTczkxZcQe0uDQ7bUum2l5g0n+tBu09sHdWQOzGJj0IolS92vedgp63MfvP9ApVTkYlel4QZQ8jH1Gf0PEw==",
                  "salt" : {
                    "value" : "6RYvlL0kAYsFyy95z4TJSw=="
                  }
                },
                "trusted" : false
              }],
              "hashMetadata" : {
                "algorithm" : "pbkdf2-sha256",
                "iterations" : 3
              }
            }""".trimMargin()

            val deserialized: VerifyNewBrowserCredentialModel.SecretData = JsonSerialization.readValue(
                    json, object : TypeReference<VerifyNewBrowserCredentialModel.SecretData>() {})

            println(deserialized)
        }
    }
}
