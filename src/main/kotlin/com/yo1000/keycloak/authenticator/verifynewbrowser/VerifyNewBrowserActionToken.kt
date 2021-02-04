package com.yo1000.keycloak.authenticator.verifynewbrowser

import com.fasterxml.jackson.annotation.JsonProperty
import org.keycloak.authentication.actiontoken.DefaultActionToken
import java.util.*

class VerifyNewBrowserActionToken(
        userId: String?,
        absoluteExpirationInSecs: Int,
        @field:JsonProperty("browserId")
        var browserId: String?
) : DefaultActionToken(
        userId,
        TOKEN_TYPE,
        absoluteExpirationInSecs,
        UUID.randomUUID()
) {
    companion object {
        const val TOKEN_TYPE = "verify-new-browser"
    }

    @Suppress("unused")
    private constructor() : this(null, 0, null) {
        // !! Don't REMOVE !! You must have this private constructor for deserializer
    }
}
