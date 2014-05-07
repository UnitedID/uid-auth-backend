package org.unitedid.auth.backend
import grails.converters.JSON
import org.unitedid.auth.hasher.YubiHSMHasher
import org.unitedid.auth.hasher.impl.Hasher

class AuthenticationController {
    def credentialType = [
            'password': 'org.unitedid.auth.factors.PasswordFactor',
            'oathtotp': 'org.unitedid.auth.factors.OathFactor',
            'oathhotp': 'org.unitedid.auth.factors.OathFactor',
            'yubikey': 'org.unitedid.auth.factors.YubiKeyFactor'
    ]


    def verifyCredentials() {
        def json = request.JSON

        Hasher hasher = (Hasher) new YubiHSMHasher()

        def fail = 0
        json.auth.factors.each {
            def credential
            if (credentialType.containsKey(it.type)) {
                credential = this.class.classLoader
                        .loadClass(credentialType[it.type], true, false)
                        .newInstance(jsonRequest: it, userId: params.id)

            }
            if (!credential.authenticate(hasher)) {
                fail++
            }
        }
        def response = [action: "auth", status: (fail == 0)]
        render response as JSON
    }
}
