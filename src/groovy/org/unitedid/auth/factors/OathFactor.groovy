package org.unitedid.auth.factors

import grails.util.Holders
import groovy.util.logging.Log4j
import org.unitedid.auth.backend.CredentialStore
import org.unitedid.auth.factors.impl.FactorImpl
import org.unitedid.auth.hasher.impl.Hasher

import javax.security.auth.login.CredentialNotFoundException

@Log4j
class OathFactor implements FactorImpl {

    static def config = Holders.config

    String aead
    def status
    int keyHandle
    int counter = 0
    def type
    String credentialId

    // The attributes below will not be stored in the credential database (see asMap())
    def userId
    def credentialStore
    def jsonRequest
    def userCode
    String nonce

    // boolean that toggles if credential store should be updated for HOTP
    def add = false

    def parseJson() {
        print " +++ " + jsonRequest
        credentialId = jsonRequest.credentialId
        nonce = jsonRequest.nonce
        userCode = jsonRequest.userCode
    }

    @Override
    def addCredential(Hasher hasher) {
        parseJson()
        add = true
        aead = jsonRequest.aead
        status = "active"
        keyHandle = jsonRequest.keyHandle
        type = jsonRequest.type

        // Authenticate to verify that the aead is valid before adding it
        def result = false
        if (type == 'oathtotp') {
            result = hasher.validateTOTP(keyHandle, nonce, aead, userCode)
        } else {
            result = hasher.validateHOTP(keyHandle, nonce, aead, counter, userCode, 10)
            if (result != 0) {
                counter = result
                result = true
            }

        }
        if (result) {
            def credential = new CredentialStore()
            credential.credential = this.asMap()
            if (credential.save(flush: true)) {
                return true
            }
        }
        return false
    }

    @Override
    def authenticate(Hasher hasher) {
        parseJson()
        def status = false

        credentialStore = CredentialStore.createCriteria().get() {
            eq 'credential.credentialId', credentialId
        }

        if (!credentialStore) {
            throw new CredentialNotFoundException("Credential not found, id: " + credentialId)
        }
        if (credentialStore.credential.status != "active") {
            throw new IllegalStateException("Credential revoked")
        }

        keyHandle = credentialStore.credential.keyHandle
        aead = credentialStore.credential.aead

        if (credentialStore.credential.type == 'oathtotp') {
            status = hasher.validateTOTP(keyHandle, nonce, aead, userCode)
        } else {
            def curCounter = credentialStore.credential.counter
            def result = hasher.validateHOTP(keyHandle, nonce, aead, curCounter, userCode, 10)
            if (result != 0) {
                counter = result
                status = true

                // Update credential if this is an authentication request
                if (!add && !updateHotpCredential()) {
                    status = false
                }
            }
        }
        return status
    }

    private updateHotpCredential() {

        def cMap = credentialStore.credential as Map
        cMap.counter = counter
        credentialStore.credential = cMap

        if (credentialStore.save(flush: true)) {
            return true
        }

        return false
    }

    private Map asMap() {
        this.class.declaredFields.findAll {
            it.modifiers == java.lang.reflect.Modifier.PRIVATE &&
                    it.name in ['aead',
                    'type',
                    'status',
                    'keyHandle',
                    'counter',
                    'type',
                    'credentialId',
            ]
        }.collectEntries {
            [it.name, this[it.name]]
        }
    }
}
