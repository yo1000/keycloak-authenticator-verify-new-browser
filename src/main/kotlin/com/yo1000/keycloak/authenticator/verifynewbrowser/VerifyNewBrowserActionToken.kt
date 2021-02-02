package com.yo1000.keycloak.authenticator.verifynewbrowser

import com.fasterxml.jackson.annotation.JsonProperty
import org.keycloak.authentication.actiontoken.DefaultActionToken
import org.keycloak.common.util.Time
import java.util.*

class VerifyNewBrowserActionToken(
        userId: String?,
        @field:JsonProperty("browserId")
        var browserId: String?
) : DefaultActionToken(
        userId,
        TOKEN_TYPE,
        Time.currentTime() + 600000, // TODO: Timeout
        UUID.randomUUID()
) {
    companion object {
        const val TOKEN_TYPE = "verify-new-browser"
    }

    private constructor() : this(null, null) {
        // !! Don't REMOVE !! You must have this private constructor for deserializer
    }
}
