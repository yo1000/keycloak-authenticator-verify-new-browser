package com.yo1000.keycloak.authenticator.newbrowsercheck

import org.keycloak.common.util.Time
import org.keycloak.credential.*
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel

class NewBrowserCheckCredentialProvider(
        private val session: KeycloakSession
) : CredentialProvider<NewBrowserCheckCredentialModel> {
    override fun getType(): String = NewBrowserCheckCredentialModel.TYPE

    override fun getCredentialTypeMetadata(context: CredentialTypeMetadataContext): CredentialTypeMetadata {
        return CredentialTypeMetadata.builder()
                .type(type)
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("new-browser-check-display-name")
                .helpText("new-browser-check-help-text")
                .removeable(false)
                .build(session)
    }

    fun getCredential(realm: RealmModel, user: UserModel): NewBrowserCheckCredentialModel? {
        return getDefaultCredential(session, realm, user)
    }

    override fun getCredentialFromModel(credential: CredentialModel): NewBrowserCheckCredentialModel {
        return NewBrowserCheckCredentialModel(credential)
    }

    override fun createCredential(realm: RealmModel, user: UserModel, credential: NewBrowserCheckCredentialModel): CredentialModel {
        if (credential.createdDate == null) {
            credential.createdDate = Time.currentTimeMillis()
        }

        return credentialStore.createCredential(realm, user, credential)
    }

    fun updateCredential(realm: RealmModel, user: UserModel, credential: NewBrowserCheckCredentialModel) {
        credentialStore.updateCredential(realm, user, credential)
    }

    override fun deleteCredential(realm: RealmModel, user: UserModel, credentialId: String): Boolean {
        return credentialStore.removeStoredCredential(realm, user, credentialId)
    }

    private val credentialStore: UserCredentialStore get() = session.userCredentialManager()
}
