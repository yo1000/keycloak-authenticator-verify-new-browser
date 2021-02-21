package com.yo1000.keycloak.authenticator.verifynewbrowser

import org.jboss.logging.Logger
import org.jboss.resteasy.spi.HttpRequest
import org.jboss.resteasy.spi.HttpResponse
import org.keycloak.Config
import org.keycloak.authentication.*
import org.keycloak.common.util.ServerCookie
import org.keycloak.common.util.Time
import org.keycloak.credential.CredentialProvider
import org.keycloak.email.EmailTemplateProvider
import org.keycloak.models.*
import org.keycloak.provider.ProviderConfigProperty
import java.net.URI
import java.time.Duration
import java.util.*
import javax.ws.rs.core.Cookie
import javax.ws.rs.core.HttpHeaders

class VerifyNewBrowserAuthenticator : Authenticator, CredentialValidator<VerifyNewBrowserCredentialProvider>,
        AuthenticatorFactory, ConfigurableAuthenticatorFactory {
    companion object {
        const val ID = "verify-new-browser-authenticator"
        const val CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID = "cookie.maxAge.browserId"
        const val CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID_DEFAULT = 60 * 60 * 24 * 365 * 10 // Default: 10 years
        const val CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE = "jwt.maxAge.authenticationChallenge"
        const val CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE_DEFAULT = 60 * 60 // Default: 1 hour
        const val COOKIE_NAME_BROWSER_ID = "VERIFY_NEW_BROWSER_ID"

        val REQUIREMENT_CHOICES = arrayOf(
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED
        )

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

        val logger: Logger = Logger.getLogger(VerifyNewBrowserAuthenticator::class.java)
    }

    /* Authenticator Factory */

    override fun getId(): String = ID

    override fun getDisplayType(): String = "Verify New Browser"

    override fun getReferenceCategory(): String = displayType

    override fun getHelpText(): String = "An email with a token URL that must be confirmed when a user signs in from a new browser."

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> = REQUIREMENT_CHOICES

    override fun isConfigurable(): Boolean = true

    override fun getConfigProperties(): MutableList<ProviderConfigProperty> = configProps

    override fun isUserSetupAllowed(): Boolean = false

    override fun init(scope: Config.Scope?) {}

    override fun postInit(factory: KeycloakSessionFactory?) {}

    override fun create(session: KeycloakSession?): Authenticator = this

    override fun close() {}

    /* Authenticator */

    override fun authenticate(context: AuthenticationFlowContext) {
        val session: KeycloakSession = context.session
        val credentialProvider: VerifyNewBrowserCredentialProvider = getCredentialProvider(session)
        val credential: VerifyNewBrowserCredentialModel? = credentialProvider.getCredential(context.realm, context.user)
        val rawBrowserId: String? = context.getCookie(COOKIE_NAME_BROWSER_ID)?.value

        if (credential?.secretData?.verifyBrowserTrusted(session, rawBrowserId) == true) {
            authenticateSuccess(context)
            return
        }

        if (credential != null) {
            authenticateChallengeByNewBrowser(context, credential)
        } else {
            authenticateChallengeByNewCredential(context)
        }
    }

    override fun action(context: AuthenticationFlowContext) {}

    private fun authenticateSuccess(
            context: AuthenticationFlowContext
    ) {
        context.success()
    }

    private fun authenticateChallengeByNewBrowser(
            context: AuthenticationFlowContext,
            credential: VerifyNewBrowserCredentialModel
    ) {
        val session: KeycloakSession = context.session
        val credentialProvider: VerifyNewBrowserCredentialProvider = getCredentialProvider(session)

        val rawBrowserId: String = UUID.randomUUID().toString()
        val challengeTokenMaxAge: Int = context.authenticatorConfig
                ?.config
                ?.get(CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE)
                ?.toInt()
                ?.takeIf { it > 0 }
                ?: CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE_DEFAULT

        val actionToken: VerifyNewBrowserActionToken = VerifyNewBrowserActionToken(
                context.user.id, Time.currentTime() + challengeTokenMaxAge, rawBrowserId)
        val actionTokenUri: String = context.getActionTokenUrl(
                actionToken.serialize(session, context.realm, context.uriInfo)).toURL().toString()

        context.sendFreeMakerEmail(actionTokenUri, challengeTokenMaxAge)

        credentialProvider.updateCredential(context.realm, context.user, credential.copy(
                secretData = credential.secretData.addBrowser(VerifyNewBrowserCredentialModel.SecretData.createBrowser(
                        session = session,
                        hashMetadata = credential.secretData.hashMetadata,
                        rawBrowserId = rawBrowserId
                ))
        ))

        val browserIdCookieMaxAge: Int = context.authenticatorConfig
                ?.config
                ?.get(CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID)
                ?.toInt()
                ?.takeIf { it > 0 }
                ?: CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID_DEFAULT

        context.addCookie(COOKIE_NAME_BROWSER_ID, rawBrowserId, browserIdCookieMaxAge)
        context.challenge(context.form().createForm("verify-new-browser-challenge.ftl"))
    }

    private fun authenticateChallengeByNewCredential(
            context: AuthenticationFlowContext
    ) {
        val session: KeycloakSession = context.session
        val credentialProvider: VerifyNewBrowserCredentialProvider = getCredentialProvider(session)

        val rawBrowserId: String = UUID.randomUUID().toString()
        val challengeTokenMaxAge: Int = context.authenticatorConfig
                ?.config
                ?.get(CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE)
                ?.toInt()
                ?.takeIf { it > 0 }
                ?: CONFIG_PROPS_JWT_MAX_AGE_AUTHN_CHALLENGE_DEFAULT

        val actionToken: VerifyNewBrowserActionToken = VerifyNewBrowserActionToken(
                context.user.id, Time.currentTime() + challengeTokenMaxAge, rawBrowserId)
        val actionTokenUri: String = context.getActionTokenUrl(
                actionToken.serialize(session, context.realm, context.uriInfo)).toURL().toString()

        context.sendFreeMakerEmail(actionTokenUri, challengeTokenMaxAge)

        val hashMetadata: VerifyNewBrowserCredentialModel.HashMetadata = VerifyNewBrowserCredentialModel.HashMetadata(
                algorithm = context.realm.passwordPolicy.hashAlgorithm
        )

        credentialProvider.createCredential(context.realm, context.user, VerifyNewBrowserCredentialModel(
                secretData = VerifyNewBrowserCredentialModel.SecretData(
                        browsers = listOf(VerifyNewBrowserCredentialModel.SecretData.createBrowser(
                                session = session,
                                hashMetadata = hashMetadata,
                                rawBrowserId = rawBrowserId
                        )),
                        hashMetadata = hashMetadata
                )
        ))

        val browserIdCookieMaxAge: Int = context.authenticatorConfig
                ?.config
                ?.get(CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID)
                ?.toInt()
                ?.takeIf { it > 0 }
                ?: CONFIG_PROPS_COOKIE_MAX_AGE_BROWSER_ID_DEFAULT

        context.addCookie(COOKIE_NAME_BROWSER_ID, rawBrowserId, browserIdCookieMaxAge)
        context.challenge(context.form().createForm("verify-new-browser-challenge.ftl"))
    }

    override fun requiresUser(): Boolean = true

    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true

    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {
        //user.addRequiredAction(UserModel.EMAIL_VERIFIED)
    }

    /* Providers */
    override fun getCredentialProvider(session: KeycloakSession): VerifyNewBrowserCredentialProvider {
        return session.getProvider(CredentialProvider::class.java, VerifyNewBrowserCredentialProviderFactory.ID) as VerifyNewBrowserCredentialProvider
    }

    /* Response utility aliases */
    private val AuthenticationFlowContext.httpResponse: HttpResponse get() = session.context.getContextObject(HttpResponse::class.java)

    private fun HttpResponse.addCookie(
            name: String?, value: String?, path: String?, domain: String?,
            comment: String?, maxAge: Int, secure: Boolean, httpOnly: Boolean
    ) {
        outputHeaders.add(HttpHeaders.SET_COOKIE, StringBuffer().also {
            ServerCookie.appendCookieValue(it, 1, name, value, path, domain, comment, maxAge, secure, httpOnly, null)
        }.toString())
    }

    private fun AuthenticationFlowContext.addCookie(
            name: String, value: String, maxAge: Int
    ) {
        val uri: URI = uriInfo.baseUriBuilder.path("realms").path(realm.name).build()

        httpResponse.addCookie(
                name, value,
                uri.rawPathWithTrailingSlash, null, null,
                maxAge, secure = false, httpOnly = true
        )
    }

    /* Request utility aliases */
    private val HttpRequest.cookies: List<Cookie> get() = httpHeaders?.cookies?.values?.toList() ?: emptyList()

    private operator fun List<Cookie>.get(name: String): Cookie? = find { it.name == name }

    private fun HttpRequest.getCookie(name: String): Cookie? = cookies[name]

    private fun AuthenticationFlowContext.getCookie(name: String): Cookie? = httpRequest.getCookie(name)

    /* Other context utility aliases */
    private fun AuthenticationFlowContext.sendFreeMakerEmail(actionUrl: String, maxAge: Int) {
        session.getProvider(EmailTemplateProvider::class.java)
                .setAuthenticationSession(session.context.authenticationSession)
                .setRealm(realm)
                .setUser(user)
                .send("verifyNewBrowserSubject", "verify-new-browser.ftl", mapOf(
                        "username" to user.username,
                        "link" to actionUrl,
                        "linkExpiration" to Duration.ofMillis(maxAge.toLong()).toHours()
                ))
    }

    private val URI.rawPathWithTrailingSlash get(): String {
        return if (rawPath.endsWith("/"))
            rawPath
        else
            "$rawPath/"
    }
}
