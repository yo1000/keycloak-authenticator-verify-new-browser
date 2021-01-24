package com.yo1000.keycloak.authenticator.newbrowsercheck

import org.jboss.logging.Logger
import org.jboss.resteasy.spi.HttpRequest
import org.jboss.resteasy.spi.HttpResponse
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.CredentialValidator
import org.keycloak.common.util.ServerCookie
import org.keycloak.common.util.Time
import org.keycloak.credential.CredentialProvider
import org.keycloak.email.EmailSenderProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.services.managers.ClientSessionCode
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.text.MessageFormat
import java.util.*
import javax.ws.rs.core.Cookie
import javax.ws.rs.core.HttpHeaders

class NewBrowserCheckAuthenticator : Authenticator, CredentialValidator<NewBrowserCheckCredentialProvider> {
    companion object {
        const val QUERYSTRING_NAME_BROWSER_CHECK_TOKEN = "nbctoken"
        const val COOKIE_NAME_BROWSER_ID = "NEW_BROWSER_CHECK_ID"
        const val COOKIE_MAX_AGE: Int = 60 * 60 * 24 * 30 // 30 days // TODO: Configurable maxAge
        const val CHALLENGE_TOKEN_MAX_AGE_MILLIS: Long = 60 * 60 * 1000L // 1 Hour(millis) // TODO: Configurable token expires

        val logger: Logger = Logger.getLogger(NewBrowserCheckAuthenticator::class.java)
    }

    override fun authenticate(context: AuthenticationFlowContext) {
        val session: KeycloakSession = context.session
        val credentialProvider: NewBrowserCheckCredentialProvider = getCredentialProvider(session)
        val credential: NewBrowserCheckCredentialModel? = credentialProvider.getCredential(context.realm, context.user)
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

    override fun action(context: AuthenticationFlowContext) {
        val session: KeycloakSession = context.session
        val credentialProvider: NewBrowserCheckCredentialProvider = getCredentialProvider(context.session)

        val credential: NewBrowserCheckCredentialModel = credentialProvider.getCredential(context.realm, context.user)
                ?: return context.failure(AuthenticationFlowError.INVALID_CREDENTIALS)

        val rawBrowserId: String = context.getCookie(COOKIE_NAME_BROWSER_ID)?.value
                ?: return context.failure(AuthenticationFlowError.INVALID_CREDENTIALS)

        val rawChallengeToken: String = context.getQueryParameter(QUERYSTRING_NAME_BROWSER_CHECK_TOKEN)?.let { URLDecoder.decode(it, "UTF-8") }
                ?: return context.failure(AuthenticationFlowError.INVALID_CREDENTIALS)

        if (credential.secretData.verifyChallengeExpiration(session, rawBrowserId, rawChallengeToken)) {
            authenticateSuccessOnAction(context, credential, rawBrowserId)
        } else {
            authenticateFailure(context, credential, rawBrowserId)
        }
    }

    private fun authenticateSuccess(
            context: AuthenticationFlowContext
    ) {
        context.success()
    }

    private fun authenticateSuccessOnAction(
            context: AuthenticationFlowContext,
            credential: NewBrowserCheckCredentialModel,
            rawBrowserId: String
    ) {
        val session: KeycloakSession = context.session
        val credentialProvider: NewBrowserCheckCredentialProvider = getCredentialProvider(session)

        credentialProvider.updateCredential(context.realm, context.user, credential.copy(
                secretData = credential.secretData.trustBrowser(session, rawBrowserId)
        ))

        logger.info("NewBrowserCheckAuthenticator success")
        authenticateSuccess(context)
    }

    private fun authenticateFailure(
            context: AuthenticationFlowContext,
            credential: NewBrowserCheckCredentialModel,
            rawBrowserId: String
    ) {
        val session: KeycloakSession = context.session
        val credentialProvider: NewBrowserCheckCredentialProvider = getCredentialProvider(session)

        credentialProvider.updateCredential(context.realm, context.user, credential.copy(
                secretData = credential.secretData.removeBrowser(session, rawBrowserId)
        ))

        logger.info("NewBrowserCheckAuthenticator failure")
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS)
    }

    private fun authenticateChallengeByNewBrowser(
            context: AuthenticationFlowContext,
            credential: NewBrowserCheckCredentialModel
    ) {
        val session: KeycloakSession = context.session
        val credentialProvider: NewBrowserCheckCredentialProvider = getCredentialProvider(session)

        val rawBrowserId: String = UUID.randomUUID().toString()
        val rawChallengeToken: String = UUID.randomUUID().toString()
        val browserCheckActionUrl = "${context.actionUri}&$QUERYSTRING_NAME_BROWSER_CHECK_TOKEN=${URLEncoder.encode(rawChallengeToken, "UTF-8")}"

        context.sendEmail("XXXX", browserCheckActionUrl)

        credentialProvider.updateCredential(context.realm, context.user, credential.copy(
                secretData = credential.secretData.addBrowser(NewBrowserCheckCredentialModel.SecretData.createBrowser(
                        session = session,
                        hashMetadata = credential.secretData.hashMetadata,
                        rawBrowserId = rawBrowserId,
                        rawChallengeToken = rawChallengeToken,
                        challengeExpires = Time.currentTimeMillis() + CHALLENGE_TOKEN_MAX_AGE_MILLIS // TODO: Configurable
                ))
        ))

        context.addCookie(COOKIE_NAME_BROWSER_ID, rawBrowserId)
        context.challenge(context.form().createForm("new-browser-check.ftl"))
    }

    private fun authenticateChallengeByNewCredential(
            context: AuthenticationFlowContext
    ) {
        val session: KeycloakSession = context.session
        val credentialProvider: NewBrowserCheckCredentialProvider = getCredentialProvider(session)

        val rawChallengeToken: String = UUID.randomUUID().toString()
        val browserCheckActionUrl = "${context.actionUri}&$QUERYSTRING_NAME_BROWSER_CHECK_TOKEN=${URLEncoder.encode(rawChallengeToken, "UTF-8")}"

        context.sendEmail("XXXX", browserCheckActionUrl)

        val rawBrowserId: String = UUID.randomUUID().toString()
        val hashMetadata: NewBrowserCheckCredentialModel.HashMetadata = NewBrowserCheckCredentialModel.HashMetadata(
                algorithm = context.realm.passwordPolicy.hashAlgorithm
        )

        credentialProvider.createCredential(context.realm, context.user, NewBrowserCheckCredentialModel(
                secretData = NewBrowserCheckCredentialModel.SecretData(
                        browsers = listOf(NewBrowserCheckCredentialModel.SecretData.createBrowser(
                                session = session,
                                hashMetadata = hashMetadata,
                                rawBrowserId = rawBrowserId,
                                rawChallengeToken = rawChallengeToken,
                                challengeExpires = Time.currentTimeMillis() + CHALLENGE_TOKEN_MAX_AGE_MILLIS // TODO: Configurable
                        )),
                        hashMetadata = hashMetadata
                )
        ))

        context.addCookie(COOKIE_NAME_BROWSER_ID, rawBrowserId)
        context.challenge(context.form().createForm("new-browser-check.ftl"))
    }

    override fun requiresUser(): Boolean = true

    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true

    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {
        //user.addRequiredAction(UserModel.EMAIL_VERIFIED)
    }

    override fun close() {}

    /* Providers */
    override fun getCredentialProvider(session: KeycloakSession): NewBrowserCheckCredentialProvider {
        return session.getProvider(CredentialProvider::class.java, NewBrowserCheckCredentialProviderFactory.ID) as NewBrowserCheckCredentialProvider
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

    private val AuthenticationFlowContext.queryParameters: Map<String, List<String>> get() = uriInfo.queryParameters ?: emptyMap()

    private fun AuthenticationFlowContext.getQueryParameter(key: String): String? = queryParameters[key]?.first()

    /* Other context utility aliases */
    private val AuthenticationFlowContext.actionUri: URI get() {
        val sessionCode: ClientSessionCode<*> = ClientSessionCode(session, realm, authenticationSession)
        authenticationSession.parentSession.timestamp = Time.currentTime()

        return getActionUrl(sessionCode.orGenerateCode)
    }

    private fun AuthenticationFlowContext.sendEmail(siteName: String, browserCheckActionUrl: String) {
        sendEmail("Keycloak Mail title",
                MessageFormat.format("""
                    [authenticate] New browser login to site {0} has been detected.
                    If this login is correct, please click on the following link to complete your login.
                    {1}
                """.trimIndent(), siteName, browserCheckActionUrl), // TODO Configurable template and title
                MessageFormat.format("""
                    [authenticate] New browser login to site {0} has been detected.<br>
                    If this login is correct, please click on the following link to complete your login.<br>
                    <a href="{1}" target="_blank" rel="noopener noreferrer">{1}</a>
                """.trimIndent(), siteName, browserCheckActionUrl) // TODO Configurable template and title
        )
    }

    private fun AuthenticationFlowContext.sendEmail(subject: String, plainText: String, htmlText: String) {
        val emailSender = session.getProvider(EmailSenderProvider::class.java)

        emailSender.send(realm.smtpConfig, user, subject, plainText, htmlText)
    }
}
