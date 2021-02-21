package com.yo1000.keycloak.authenticator.verifynewbrowser

import org.jboss.resteasy.spi.HttpRequest
import org.keycloak.Config
import org.keycloak.authentication.*
import org.keycloak.credential.CredentialProvider
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.*
import org.keycloak.provider.ProviderConfigProperty
import java.lang.IllegalStateException
import java.net.URI
import java.util.*
import javax.ws.rs.core.Cookie

class RegistrationNewBrowser : FormAction, FormActionFactory {
    companion object {
        const val ID = "registration-new-browser-action"
        private const val CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID = "cookie.maxAge.browserId"
        private const val CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID_DEFAULT = 60 * 60 * 24 * 365 * 10 // Default: 10 years

        val REQUIREMENT_CHOICES = arrayOf(
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        )

        val configProps: MutableList<ProviderConfigProperty> = mutableListOf(
                ProviderConfigProperty().also {
                    it.name = CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID
                    it.label = "Browser identification cookie Max age"
                    it.type = ProviderConfigProperty.STRING_TYPE
                    it.helpText = "Max age in seconds of the Browser ID Cookie"
                    it.defaultValue = CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID_DEFAULT
                }
        )
    }

    /* FormAction Metadata */

    override fun getId(): String = ID

    override fun getDisplayType(): String = "New Browser"

    override fun getReferenceCategory(): String = displayType

    override fun getHelpText(): String = "Store New Browser ID in user data."

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> = REQUIREMENT_CHOICES

    override fun isConfigurable(): Boolean = true

    override fun getConfigProperties(): List<ProviderConfigProperty>? = configProps

    override fun isUserSetupAllowed(): Boolean = false

    override fun init(scope: Config.Scope) {}

    override fun postInit(factory: KeycloakSessionFactory) {}

    override fun create(session: KeycloakSession?): FormAction = this

    override fun close() {}

    /* FormAction */

    override fun validate(context: ValidationContext) {
        context.success()
    }

    override fun buildPage(context: FormContext, form: LoginFormsProvider) {
        if (context.getCookie(VerifyNewBrowserAuthenticator.COOKIE_NAME_BROWSER_ID) == null) {
            val browserIdCookieMaxAge: Int = context.authenticatorConfig
                    ?.config
                    ?.get(CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID)
                    ?.toInt()
                    ?.takeIf { it > 0 }
                    ?: CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID_DEFAULT

            form.addCookie(
                    VerifyNewBrowserAuthenticator.COOKIE_NAME_BROWSER_ID,
                    UUID.randomUUID().toString(),
                    context.uriInfo.baseUriBuilder.path("realms").path(context.realm.name).build().rawPathWithTrailingSlash,
                    browserIdCookieMaxAge
            )
        }
    }

    override fun success(context: FormContext) {
        val session: KeycloakSession = context.session
        val realm: RealmModel = context.realm
        val user: UserModel = context.user
        val credentialProvider: VerifyNewBrowserCredentialProvider = session.getCredentialProvider()
        val cookieRawBrowserId: String = context.getCookie(VerifyNewBrowserAuthenticator.COOKIE_NAME_BROWSER_ID)?.value
                ?: throw IllegalStateException("BrowserId contained to cookie does not exist")

        val hashMetadata: VerifyNewBrowserCredentialModel.HashMetadata = VerifyNewBrowserCredentialModel.HashMetadata(
                algorithm = context.realm.passwordPolicy.hashAlgorithm
        )

        credentialProvider.createCredential(realm, user, VerifyNewBrowserCredentialModel(
                secretData = VerifyNewBrowserCredentialModel.SecretData(
                        browsers = listOf(VerifyNewBrowserCredentialModel.SecretData.createBrowser(
                                session = session,
                                hashMetadata = hashMetadata,
                                rawBrowserId = cookieRawBrowserId
                        ).copy(
                                trusted = true
                        )),
                        hashMetadata = hashMetadata
                )
        ))
    }

    override fun requiresUser(): Boolean = false

    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true

    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {}

    private val URI.rawPathWithTrailingSlash get(): String {
        return if (rawPath.endsWith("/"))
            rawPath
        else
            "$rawPath/"
    }

    private fun LoginFormsProvider.addCookie(
            name: String?, value: String?, path: String?, domain: String?,
            comment: String?, maxAge: Int, secure: Boolean, httpOnly: Boolean
    ) {
        setResponseHeader("Set-Cookie",
                "$name=$value${
                comment?.let { "; Comment=$it" } ?: ""}${
                path?.let { "; Path=$it" } ?: ""}${
                domain?.let { "; Domain=$it" } ?: ""}${
                "; Max-Age=$maxAge"}${
                if (secure) "; Secure" else ""}${
                if (httpOnly) "; HttpOnly" else ""}")
    }

    private fun LoginFormsProvider.addCookie(
            name: String, value: String, path: String, maxAge: Int
    ) {
        addCookie(
                name, value,
                path, null, null,
                maxAge, secure = false, httpOnly = true
        )
    }

    /* Providers */
    private fun KeycloakSession.getCredentialProvider(): VerifyNewBrowserCredentialProvider {
        return this.getProvider(CredentialProvider::class.java, VerifyNewBrowserCredentialProviderFactory.ID) as VerifyNewBrowserCredentialProvider
    }

    /* Request utility aliases */
    private val HttpRequest.cookies: List<Cookie> get() = httpHeaders?.cookies?.values?.toList() ?: emptyList()

    private operator fun List<Cookie>.get(name: String): Cookie? = find { it.name == name }

    private fun HttpRequest.getCookie(name: String): Cookie? = cookies[name]

    private fun FormContext.getCookie(name: String): Cookie? = httpRequest.getCookie(name)
}