package com.yo1000.keycloak.authenticator.newbrowsercheck

import org.keycloak.credential.CredentialProvider
import org.keycloak.credential.CredentialProviderFactory
import org.keycloak.models.KeycloakSession

class NewBrowserCheckCredentialProviderFactory : CredentialProviderFactory<NewBrowserCheckCredentialProvider> {
    companion object {
        const val ID = "new-browser-check"
    }

    override fun getId(): String = ID

    override fun create(session: KeycloakSession): CredentialProvider<*> {
        return NewBrowserCheckCredentialProvider(session)
    }
}
