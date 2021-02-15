package com.yo1000.keycloak.authenticator.verifynewbrowser

import org.keycloak.authentication.AuthenticationProcessor
import org.keycloak.authentication.actiontoken.AbstractActionTokenHander
import org.keycloak.authentication.actiontoken.ActionTokenContext
import org.keycloak.credential.CredentialProvider
import org.keycloak.events.Errors
import org.keycloak.events.EventType
import org.keycloak.exceptions.TokenVerificationException
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.managers.AuthenticationManager
import org.keycloak.services.messages.Messages
import org.keycloak.sessions.AuthenticationSessionModel
import javax.ws.rs.core.Cookie
import javax.ws.rs.core.Response
import javax.ws.rs.core.UriInfo

class VerifyNewBrowserActionTokenHandler : AbstractActionTokenHander<VerifyNewBrowserActionToken>(
        VerifyNewBrowserActionToken.TOKEN_TYPE,
        VerifyNewBrowserActionToken::class.java,
        Messages.STALE_VERIFY_EMAIL_LINK,
        EventType.EXECUTE_ACTION_TOKEN,
        Errors.INVALID_TOKEN
) {
    companion object {
        const val COOKIE_NAME_BROWSER_ID = "VERIFY_NEW_BROWSER_ID"
    }

    override fun handleToken(token: VerifyNewBrowserActionToken, tokenContext: ActionTokenContext<VerifyNewBrowserActionToken>): Response {
        val keycloakSession: KeycloakSession = tokenContext.session
        val authnSession: AuthenticationSessionModel = tokenContext.authenticationSession
        val realm: RealmModel = tokenContext.realm
        val user = authnSession.authenticatedUser
        val uriInfo: UriInfo = tokenContext.uriInfo
        val conn = tokenContext.clientConnection
        val event = tokenContext.event
        val request = tokenContext.request
        val credentialProvider: VerifyNewBrowserCredentialProvider = keycloakSession.getCredentialProvider()

        val tokenRawBrowserId: String = token.browserId
                ?: throw TokenVerificationException(token, "BrowserId linked to token does not exist")

        val credential: VerifyNewBrowserCredentialModel = credentialProvider.getCredential(realm, user)
                ?: throw TokenVerificationException(token, "Credential linked to token does not exist")

        credentialProvider.updateCredential(realm, user,  credential.copy(
                secretData = credential.secretData.trustBrowser(keycloakSession, tokenRawBrowserId)
        ))

        val cookieRawBrowserId: String? = request.httpHeaders.cookies[COOKIE_NAME_BROWSER_ID]?.value

        if (tokenRawBrowserId == cookieRawBrowserId) {
            val clientSessionContext = AuthenticationProcessor.attachSession(
                    authnSession,
                    null,
                    keycloakSession,
                    realm,
                    conn,
                    event
            )

            tokenContext.event.success()

            return AuthenticationManager.redirectAfterSuccessfulFlow(
                    keycloakSession,
                    realm,
                    clientSessionContext.clientSession.userSession,
                    clientSessionContext,
                    request,
                    uriInfo,
                    conn,
                    event,
                    authnSession
            )
        } else {
            return keycloakSession.getProvider(LoginFormsProvider::class.java)
                    .setAuthenticationSession(authnSession)
                    .setMessageAttribute("completeVerifyNewBrowserHeader")
                    .setMessageAttribute("completeVerifyNewBrowserBody")
                    .createForm("verify-new-browser-complete.ftl")
        }
    }

    override fun canUseTokenRepeatedly(token: VerifyNewBrowserActionToken?, tokenContext: ActionTokenContext<VerifyNewBrowserActionToken>?): Boolean {
        return false
    }

    private fun LoginFormsProvider.setMessageAttribute(message: String, vararg parameters: String): LoginFormsProvider {
        this.setAttribute(message, this.getMessage(message, *parameters))
        return this
    }

    private fun KeycloakSession.getCredentialProvider(): VerifyNewBrowserCredentialProvider {
        return this.getProvider(CredentialProvider::class.java, VerifyNewBrowserCredentialProviderFactory.ID) as VerifyNewBrowserCredentialProvider
    }

    private operator fun List<Cookie>.get(name: String): Cookie? = find { it.name == name }
}
