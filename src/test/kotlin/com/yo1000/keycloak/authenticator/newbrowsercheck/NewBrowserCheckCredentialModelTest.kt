package com.yo1000.keycloak.authenticator.newbrowsercheck

import com.fasterxml.jackson.core.type.TypeReference
import org.junit.jupiter.api.Test
import org.keycloak.util.JsonSerialization

class NewBrowserCheckCredentialModelTest {
    class SecretDataTest {
        @Test
        fun testSerde() {
            val json: String = """{
              "browsers" : [ {
                "id" : {
                  "value" : "ozDPTczkxZcQe0uDQ7bUum2l5g0n+tBu09sHdWQOzGJj0IolS92vedgp63MfvP9ApVTkYlel4QZQ8jH1Gf0PEw==",
                  "salt" : {
                    "value" : "6RYvlL0kAYsFyy95z4TJSw=="
                  }
                },
                "trusted" : false,
                "challenge" : {
                  "token" : {
                    "value" : "4ZwNYw6mkk4aadfBMjqRILfAprgIa+AYRo2GFQFIFkWbd4RpE2mHs1YjMpnFPPjLsR8NRQCEaboG0qGFzWcjtg==",
                    "salt" : {
                      "value" : "Ey4HhTxkdK38SBvxUnBH-Q=="
                    }
                  },
                  "expires" : 1611464994049
                }
              } ],
              "hashMetadata" : {
                "algorithm" : "pbkdf2-sha256",
                "iterations" : 3
              }
            }""".trimMargin()

            val deserialized: NewBrowserCheckCredentialModel.SecretData = JsonSerialization.readValue(
                    json, object : TypeReference<NewBrowserCheckCredentialModel.SecretData>() {})

            println(deserialized)
        }
    }
}