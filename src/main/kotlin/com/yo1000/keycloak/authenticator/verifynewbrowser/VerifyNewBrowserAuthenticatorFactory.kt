package com.yo1000.keycloak.authenticator.verifynewbrowser

import org.keycloak.Config
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.authentication.ConfigurableAuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel.Requirement
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty

class VerifyNewBrowserAuthenticatorFactory : AuthenticatorFactory, ConfigurableAuthenticatorFactory {
    companion object {
        const val ID = "verify-new-browser-authenticator"
        const val CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID = "cookie.maxAge.browserId"
        const val CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID_DEFAULT = 60 * 60 * 24 * 365 * 10 // Default: 10 years
        const val CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE = "jwt.maxAge.authenticationChallenge"
        const val CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE_DEFAULT = 60 * 60 // Default: 1 hour

        val REQUIREMENT_CHOICES = arrayOf(
                Requirement.REQUIRED,
                Requirement.ALTERNATIVE,
                Requirement.DISABLED
        )

        val AUTHENTICATOR = VerifyNewBrowserAuthenticator()

        val configProps: MutableList<ProviderConfigProperty> = mutableListOf(
                ProviderConfigProperty().also {
                    it.name = CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID
                    it.label = "Browser identification cookie Max age"
                    it.type = ProviderConfigProperty.STRING_TYPE
                    it.helpText = "Max age in seconds of the Browser ID Cookie"
                    it.defaultValue = CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID_DEFAULT
                },
                ProviderConfigProperty().also {
                    it.name = CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE
                    it.label = "Authentication challenge JWT Max age"
                    it.type = ProviderConfigProperty.STRING_TYPE
                    it.helpText = "Max age in seconds of the Authentication challenge JWT"
                    it.defaultValue = CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE_DEFAULT
                }
        )
    }

    override fun getId(): String = ID

    override fun getDisplayType(): String = "Verify New Browser"

    override fun getReferenceCategory(): String = displayType

    override fun getHelpText(): String = "An email with a token URL that must be confirmed when a user signs in from a new browser."

    override fun getRequirementChoices(): Array<Requirement> = REQUIREMENT_CHOICES

    override fun isConfigurable(): Boolean = true

    override fun getConfigProperties(): MutableList<ProviderConfigProperty> = configProps

    override fun isUserSetupAllowed(): Boolean = false

    override fun init(scope: Config.Scope?) {}

    override fun postInit(factory: KeycloakSessionFactory?) {}

    override fun create(session: KeycloakSession?): Authenticator = AUTHENTICATOR

    override fun close() {}
}
