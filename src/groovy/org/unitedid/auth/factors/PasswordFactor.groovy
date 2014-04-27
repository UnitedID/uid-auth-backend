package org.unitedid.auth.factors
import grails.util.Holders
import groovy.util.logging.Log4j
import org.unitedid.auth.backend.CredentialStore
import org.unitedid.auth.factors.impl.Factor
import org.unitedid.auth.hasher.impl.Hasher

import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.security.auth.login.CredentialNotFoundException

@Log4j
class PasswordFactor implements Factor {

    String derivedKey
    int iterations
    def status
    int keyHandle
    String salt
    def type = "password"
    String credentialId

    // h1 may not be stored in the credential storage
    def H1
    // userId may not be stored in the credential storage
    def userId
    // credentialStore may not be stored in the credential storage
    def credentialStore

    static def config = Holders.config

    public PasswordFactor(String action, Object req, String userId) {
        this.userId = userId
        credentialId = req.credentialId

        if (action == "addCred") {
            status = "active"
            iterations = (int) config.pbkdf2.iterations
            keyHandle = (int) config.yhsm.hmacKeyHandle
            H1 = req.H1
        } else if (action == "authenticate") {
            credentialStore = CredentialStore.createCriteria().get {
                eq 'credential.credentialId', credentialId
            }
            if (!credentialStore) {
                throw new CredentialNotFoundException("Credential not found, id: " + credentialId)
            }
            if (credentialStore.credential.status != "active") {
                throw new IllegalStateException("Credential revoked")
            }
            H1 = req.H1
            salt = credentialStore.credential.salt
            iterations = credentialStore.credential.iterations
            keyHandle = credentialStore.credential.keyHandle
        }

    }

    def addCredential(Hasher hasher) {
        salt = hasher.random(16)
        calculateCredentialHash(hasher)

        def credential = new CredentialStore()
        credential.credential = this.asMap()
        if (credential.save(flush: true)) {
            return true
        }
        return false
    }

    def authenticate(Hasher hasher) {
        calculateCredentialHash(hasher)

        //TODO: add a slow verifier method
        if (derivedKey == credentialStore.credential.derivedKey) {
            return true
        }
        return false
    }

    def calculateCredentialHash(Hasher hasher) {
        String T1 = "A" + userId + credentialId + H1
        PBEKeySpec keySpec = new PBEKeySpec(T1.toCharArray(), salt.decodeHex(), iterations, 64 * 8)
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        SecretKey secretKey = keyFactory.generateSecret(keySpec)
        String T2 = secretKey.getEncoded().encodeHex()

        byte[] localSalt = hasher.hmacSha1(keyHandle, T2.decodeHex())
        keySpec = new PBEKeySpec(T2.toCharArray(), localSalt, 1, 64 * 8)
        secretKey = keyFactory.generateSecret(keySpec)
        derivedKey = secretKey.getEncoded().encodeHex()
    }

    public Map asMap() {
        this.class.declaredFields.findAll {
            it.modifiers == java.lang.reflect.Modifier.PRIVATE &&
                    it.name in ['derivedKey',
                    'salt',
                    'iterations',
                    'status',
                    'keyHandle',
                    'type',
                    'credentialId'
            ]
        }.collectEntries {
            [it.name, this[it.name]]
        }
    }
}
