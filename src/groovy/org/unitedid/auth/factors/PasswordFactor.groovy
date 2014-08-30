package org.unitedid.auth.factors
import grails.util.Holders
import groovy.util.logging.Log4j
import org.unitedid.auth.backend.CredentialStore
import org.unitedid.auth.factors.impl.FactorImpl
import org.unitedid.auth.hasher.impl.Hasher

import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.security.auth.login.CredentialNotFoundException

@Log4j
class PasswordFactor implements FactorImpl {

    static def config = Holders.config

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

    def jsonRequest

    def parseJson() {
        credentialId = jsonRequest.credentialId
        H1 = jsonRequest.H1
    }

    @Override
    def addCredential(Hasher hasher) {
        parseJson()

        status = "active"
        iterations = (int) config.pbkdf2.iterations
        keyHandle = (int) config.yhsm.hmacKeyHandle
        salt = hasher.random(16)
        calculateCredentialHash(hasher)

        def credential = new CredentialStore()
        credential.credential = this.asMap()
        if (credential.save(flush: true)) {
            log.debug("Password credential added with id " + credentialId)
            return true
        }
        return false
    }

    @Override
    def authenticate(Hasher hasher) {
        parseJson()

        credentialStore = CredentialStore.createCriteria().get {
            eq 'credential.credentialId', credentialId
        }
        if (!credentialStore) {
            throw new CredentialNotFoundException("Credential not found, id: " + credentialId)
        }
        if (credentialStore.credential.status != "active") {
            throw new IllegalStateException("Credential revoked")
        }

        salt = credentialStore.credential.salt
        iterations = credentialStore.credential.iterations
        keyHandle = credentialStore.credential.keyHandle
        calculateCredentialHash(hasher)

        //TODO: add a slow verifier method
        if (derivedKey == credentialStore.credential.derivedKey) {
            log.debug("Password authentication successful for credentialId " + credentialId)
            return true
        }

        log.debug("Password authentication failed for credentialId " + credentialId)

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
