package com.yo1000.keycloak.authenticator.verifynewbrowser

import org.keycloak.common.util.Time
import org.keycloak.credential.*
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel

class VerifyNewBrowserCredentialProvider(
        private val session: KeycloakSession
) : CredentialProvider<VerifyNewBrowserCredentialModel> {
    override fun getType(): String = VerifyNewBrowserCredentialModel.TYPE

    override fun getCredentialTypeMetadata(context: CredentialTypeMetadataContext): CredentialTypeMetadata {
        return CredentialTypeMetadata.builder()
                .type(type)
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("verify-new-browser-display-name")
                .helpText("verify-new-browser-help-text")
                .removeable(false)
                .build(session)
    }

    fun getCredential(realm: RealmModel, user: UserModel): VerifyNewBrowserCredentialModel? {
        return getDefaultCredential(session, realm, user)
    }

    override fun getCredentialFromModel(credential: CredentialModel): VerifyNewBrowserCredentialModel {
        return VerifyNewBrowserCredentialModel(credential)
    }

    override fun createCredential(realm: RealmModel, user: UserModel, credentialVerify: VerifyNewBrowserCredentialModel): CredentialModel {
        if (credentialVerify.createdDate == null) {
            credentialVerify.createdDate = Time.currentTimeMillis()
        }

        return credentialStore.createCredential(realm, user, credentialVerify)
    }

    fun updateCredential(realm: RealmModel, user: UserModel, credentialVerify: VerifyNewBrowserCredentialModel) {
        credentialStore.updateCredential(realm, user, credentialVerify)
    }

    override fun deleteCredential(realm: RealmModel, user: UserModel, credentialId: String): Boolean {
        return credentialStore.removeStoredCredential(realm, user, credentialId)
    }

    private val credentialStore: UserCredentialStore get() = session.userCredentialManager()
}
