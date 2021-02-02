package com.yo1000.keycloak.authenticator.verifynewbrowser

import org.keycloak.credential.CredentialProvider
import org.keycloak.credential.CredentialProviderFactory
import org.keycloak.models.KeycloakSession

class VerifyNewBrowserCredentialProviderFactory : CredentialProviderFactory<VerifyNewBrowserCredentialProvider> {
    companion object {
        const val ID = "verify-new-browser"
    }

    override fun getId(): String = ID

    override fun create(session: KeycloakSession): CredentialProvider<*> {
        return VerifyNewBrowserCredentialProvider(session)
    }
}
