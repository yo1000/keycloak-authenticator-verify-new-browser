package com.yo1000.keycloak.authenticator.verifynewbrowser

import org.jboss.logging.Logger
import org.jboss.resteasy.spi.HttpRequest
import org.jboss.resteasy.spi.HttpResponse
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.CredentialValidator
import org.keycloak.common.util.ServerCookie
import org.keycloak.credential.CredentialProvider
import org.keycloak.email.EmailTemplateProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import java.time.Duration
import java.util.*
import javax.ws.rs.core.Cookie
import javax.ws.rs.core.HttpHeaders

class VerifyNewBrowserAuthenticator : Authenticator, CredentialValidator<VerifyNewBrowserCredentialProvider> {
    companion object {
        const val COOKIE_NAME_BROWSER_ID = "VERIFY_NEW_BROWSER_ID"
        const val COOKIE_MAX_AGE: Int = 60 * 60 * 24 * 30 // 30 days // TODO: Configurable maxAge
        const val CHALLENGE_TOKEN_MAX_AGE_MILLIS: Long = 60 * 60 * 1000L // 1 Hour(millis) // TODO: Configurable token expires

        val logger: Logger = Logger.getLogger(VerifyNewBrowserAuthenticator::class.java)
    }

    override fun authenticate(context: AuthenticationFlowContext) {
        val session: KeycloakSession = context.session
        val credentialProviderVerify: VerifyNewBrowserCredentialProvider = getCredentialProvider(session)
        val credential: VerifyNewBrowserCredentialModel? = credentialProviderVerify.getCredential(context.realm, context.user)
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

        val actionToken: VerifyNewBrowserActionToken = VerifyNewBrowserActionToken(context.user.id, rawBrowserId)
        val actionTokenUri: String = context.getActionTokenUrl(actionToken.serialize(session, context.realm, context.uriInfo)).toURL().toString()

        context.sendFreeMakerEmail(actionTokenUri, CHALLENGE_TOKEN_MAX_AGE_MILLIS) // TODO: Configurable

        credentialProvider.updateCredential(context.realm, context.user, credential.copy(
                secretData = credential.secretData.addBrowser(VerifyNewBrowserCredentialModel.SecretData.createBrowser(
                        session = session,
                        hashMetadata = credential.secretData.hashMetadata,
                        rawBrowserId = rawBrowserId
                ))
        ))

        context.addCookie(COOKIE_NAME_BROWSER_ID, rawBrowserId)
        context.challenge(context.form().createForm("verify-new-browser-challenge.ftl"))
    }

    private fun authenticateChallengeByNewCredential(
            context: AuthenticationFlowContext
    ) {
        val session: KeycloakSession = context.session
        val credentialProvider: VerifyNewBrowserCredentialProvider = getCredentialProvider(session)

        val rawBrowserId: String = UUID.randomUUID().toString()
        val actionToken: VerifyNewBrowserActionToken = VerifyNewBrowserActionToken(context.user.id, rawBrowserId)
        val actionTokenUri: String = context.getActionTokenUrl(actionToken.serialize(session, context.realm, context.uriInfo)).toURL().toString()

        context.sendFreeMakerEmail(actionTokenUri, CHALLENGE_TOKEN_MAX_AGE_MILLIS) // TODO: Configurable

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

        context.addCookie(COOKIE_NAME_BROWSER_ID, rawBrowserId)
        context.challenge(context.form().createForm("verify-new-browser-challenge.ftl"))
    }

    override fun requiresUser(): Boolean = true

    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true

    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {
        //user.addRequiredAction(UserModel.EMAIL_VERIFIED)
    }

    override fun close() {}

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
            name: String, value: String
    ) {
        val uri = uriInfo.baseUriBuilder.path("realms").path(realm.name).build()

        httpResponse.addCookie(
                name, value,
                uri.rawPath, null, null,
                COOKIE_MAX_AGE, secure = false, httpOnly = true
        )
    }

    /* Request utility aliases */
    private val HttpRequest.cookies: List<Cookie> get() = httpHeaders?.cookies?.values?.toList() ?: emptyList()

    private operator fun List<Cookie>.get(name: String): Cookie? = find { it.name == name }

    private fun HttpRequest.getCookie(name: String): Cookie? = cookies[name]

    private fun AuthenticationFlowContext.getCookie(name: String): Cookie? = httpRequest.getCookie(name)

    /* Other context utility aliases */
    private fun AuthenticationFlowContext.sendFreeMakerEmail(actionUrl: String, expiration: Long) {
        session.getProvider(EmailTemplateProvider::class.java)
                .setAuthenticationSession(session.context.authenticationSession)
                .setRealm(realm)
                .setUser(user)
                .send("verifyNewBrowserSubject", "verify-new-browser.ftl", mapOf(
                        "username" to user.username,
                        "link" to actionUrl,
                        "linkExpiration" to Duration.ofMillis(expiration).toHours()
                ))
    }
}
