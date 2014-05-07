package org.unitedid.auth.backend
import grails.converters.JSON
import org.unitedid.auth.hasher.YubiHSMHasher
import org.unitedid.auth.hasher.impl.Hasher

class CredentialController {

    def add() {
        def credentialType = [
                'password': 'org.unitedid.auth.factors.PasswordFactor',
                'oathtotp': 'org.unitedid.auth.factors.OathFactor',
                'oathhotp': 'org.unitedid.auth.factors.OathFactor',
                'yubikey': 'org.unitedid.auth.factors.YubiKeyFactor'
        ]
        def json = request.JSON

        if (!json?.addCreds?.version || !json?.addCreds?.userId || !json?.addCreds?.factors) {
            throw new IllegalArgumentException("Bad JSON payload")
        }

        Hasher hasher = (Hasher) new YubiHSMHasher()

        def fail = 0

        json.addCreds.factors.each {
            def credential
            if (credentialType.containsKey(it.type)) {
                credential = this.class.classLoader
                        .loadClass(credentialType[it.type], true, false)
                        .newInstance(jsonRequest: it, userId: params.id)
            } else {
                def response = [action: "addCred", status: false]
                render response as JSON
                return
            }
            if(!credential.addCredential(hasher)) {
                fail++
            }
        }
        def response = [action: "addCred", status: (fail == 0)]
        render response as JSON
    }
    def update() {

    }

    def revoke() {
        def response = [action: "revokeCred", status: false]

        CredentialStore credential = CredentialStore.createCriteria().get() {
            eq 'credential.credentialId', params.credentialId
        }

        def cMap = credential.credential as Map
        cMap.status = "revoked"
        credential.credential = cMap

        if (credential.save(failOnError:true, flush: true)) {
            response.status = true
        }

        render response as JSON
    }
}
