package com.yo1000.keycloak.authenticator.newbrowsercheck

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.core.type.TypeReference
import org.keycloak.common.util.Time
import org.keycloak.credential.CredentialModel
import org.keycloak.credential.hash.PasswordHashProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.PasswordPolicy
import org.keycloak.models.credential.PasswordCredentialModel
import org.keycloak.models.credential.dto.PasswordCredentialData
import org.keycloak.models.credential.dto.PasswordSecretData
import org.keycloak.util.JsonSerialization
import java.util.*
import kotlin.random.Random

class NewBrowserCheckCredentialModel(
        id: String = UUID.randomUUID().toString(),
        type: String = TYPE,
        userLabel: String? = null,
        createdDate: Long = Time.currentTimeMillis(),
        val secretData: SecretData
) : CredentialModel() {
    companion object {
        const val TYPE = "new-browser-check"
    }

    init {
        this.id = id
        this.type = type
        this.userLabel = userLabel
        this.createdDate = createdDate
        setSecretData(secretData.toJson())
    }

    constructor(
            credentialModel: CredentialModel
    ) : this(
            id = credentialModel.id,
            type = credentialModel.type,
            userLabel = credentialModel.userLabel,
            createdDate = credentialModel.createdDate,
            secretData = SecretData.of(credentialModel.secretData)
    )

    fun copy(
            id: String = this.id,
            type: String = this.type,
            userLabel: String? = this.userLabel,
            createdDate: Long = this.createdDate,
            secretData: SecretData = this.secretData
    ): NewBrowserCheckCredentialModel = NewBrowserCheckCredentialModel(
            id = id,
            type = type,
            userLabel = userLabel,
            createdDate = createdDate,
            secretData = secretData
    )

    data class SecretData @JsonCreator constructor(
            @JsonProperty("browsers")
            val browsers: List<Browser>,
            @JsonProperty("hashMetadata")
            val hashMetadata: HashMetadata
    ) {
        companion object {
            fun of(json: String): SecretData {
                return JsonSerialization.readValue(json, object : TypeReference<SecretData>() {})
            }

            fun createBrowser(
                    session: KeycloakSession,
                    hashMetadata: HashMetadata,
                    rawBrowserId: String,
                    rawChallengeToken: String,
                    challengeExpires: Long
            ): Browser {
                return Browser(
                        id = encode(session, hashMetadata, rawBrowserId),
                        trusted = false,
                        challenge = Challenge(
                                token = encode(session, hashMetadata, rawChallengeToken),
                                expires = challengeExpires
                        )
                )
            }

            private fun encode(session: KeycloakSession, hashMetadata: HashMetadata, raw: String): Hash {
                return getHashProvider(session, hashMetadata.algorithm).encodedCredential(raw, hashMetadata.iterations).let {
                    Hash(
                            value = it.passwordSecretData.value,
                            salt = Salt(it.passwordSecretData.salt)
                    )
                }
            }

            private fun getHashProvider(session: KeycloakSession, algorithm: String): PasswordHashProvider {
                return session.getProvider(PasswordHashProvider::class.java, algorithm)
                        ?: session.getProvider(PasswordHashProvider::class.java, PasswordPolicy.HASH_ALGORITHM_DEFAULT)
            }
        }

        fun toJson(): String {
            return JsonSerialization.writeValueAsString(this)
        }

        fun addBrowser(browser: Browser): SecretData {
            return updateBrowsers(browsers + browser)
        }

        fun trustBrowser(session: KeycloakSession, rawBrowserId: String): SecretData {
            val trustedBrowser: Browser = getBrowser(session, rawBrowserId)?.copy(trusted = true)
                    ?: throw IllegalArgumentException("browser is not found")

            return removeBrowser(session, rawBrowserId).addBrowser(trustedBrowser)
        }

        fun removeBrowser(session: KeycloakSession, rawBrowserId: String): SecretData {
            return updateBrowsers(browsers.filterNot { verify(session, rawBrowserId, it.id) })
        }

        fun verifyBrowserTrusted(session: KeycloakSession, rawBrowserId: String?): Boolean {
            if (rawBrowserId == null) return false

            return browsers.find {
                verify(session, rawBrowserId, it.id)
            }?.trusted ?: false
        }

        fun verifyChallengeExpiration(session: KeycloakSession, rawBrowserId: String?, rawChallengeToken: String?): Boolean {
            if (rawBrowserId == null) return false
            if (rawChallengeToken == null) return false

            return getBrowser(session, rawBrowserId)?.challenge?.let {
                verify(session, rawChallengeToken, it.token) && it.expires >= Time.currentTimeMillis()
            } ?: false
        }

        private fun updateBrowsers(browsers: List<Browser>): SecretData {
            return copy(browsers = browsers)
        }

        private fun getBrowser(session: KeycloakSession, rawBrowserId: String): Browser? {
            return browsers.find { verify(session, rawBrowserId, it.id) }
        }

        private fun verify(session: KeycloakSession, raw: String, hash: Hash): Boolean {
            return getHashProvider(session).verify(raw, PasswordCredentialModel.createFromValues(
                    PasswordCredentialData(hashMetadata.iterations, hashMetadata.algorithm),
                    PasswordSecretData(hash.value, hash.salt.toByteArray())
            ))
        }

        private fun getHashProvider(session: KeycloakSession): PasswordHashProvider {
            return Companion.getHashProvider(session, hashMetadata.algorithm)
        }
    }

    data class Browser @JsonCreator constructor(
            @JsonProperty("id")
            val id: Hash,
            @JsonProperty("trusted")
            val trusted: Boolean = false,
            @JsonProperty("challenge")
            val challenge: Challenge
    )

    data class Challenge @JsonCreator constructor(
            @JsonProperty("token")
            val token: Hash,
            @JsonProperty("expires")
            val expires: Long
    )

    data class Hash @JsonCreator constructor(
            @JsonProperty("value")
            val value: String,
            @JsonProperty("salt")
            val salt: Salt
    )

    data class Salt @JsonCreator constructor(
            @JsonProperty("value")
            val value: String
    ) {
        constructor(salt: ByteArray) : this(
            Base64.getUrlEncoder().encodeToString(salt)
        )

        fun toByteArray(): ByteArray {
            return Base64.getUrlDecoder().decode(this.value)
        }

        override fun toString(): String {
            return value
        }
    }

    data class HashMetadata @JsonCreator constructor(
            @JsonProperty("algorithm")
            val algorithm: String,
            @JsonProperty("iterations")
            val iterations: Int = Random.nextInt(3, 5)
    )
}
