package com.yo1000.keycloak.authenticator.newbrowsercheck

import org.keycloak.Config
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.authentication.ConfigurableAuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel.Requirement
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty

class NewBrowserCheckAuthenticatorFactory : AuthenticatorFactory, ConfigurableAuthenticatorFactory {
    companion object {
        const val ID = "new-browser-check-authenticator"

        val REQUIREMENT_CHOICES = arrayOf(
                Requirement.REQUIRED,
                Requirement.ALTERNATIVE,
                Requirement.DISABLED
        )

        val AUTHENTICATOR = NewBrowserCheckAuthenticator()

        val configProps: MutableList<ProviderConfigProperty> = mutableListOf()
    }

    override fun getId(): String = ID

    override fun getDisplayType(): String = "New Browser Check"

    override fun getReferenceCategory(): String = displayType

    override fun getHelpText(): String = "An email with a token URL that must be confirmed when a user signs in from a new browser."

    override fun getRequirementChoices(): Array<Requirement> = REQUIREMENT_CHOICES

    override fun isConfigurable(): Boolean = false

    override fun getConfigProperties(): MutableList<ProviderConfigProperty> = configProps

    override fun isUserSetupAllowed(): Boolean = false

    override fun init(scope: Config.Scope?) {}

    override fun postInit(factory: KeycloakSessionFactory?) {}

    override fun create(session: KeycloakSession?): Authenticator = AUTHENTICATOR

    override fun close() {}
}
