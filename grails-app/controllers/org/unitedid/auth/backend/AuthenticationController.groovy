package org.unitedid.auth.backend

import grails.converters.JSON
import org.unitedid.auth.factors.PasswordFactor
import org.unitedid.auth.hasher.YubiHSMHasher
import org.unitedid.auth.hasher.impl.Hasher

class AuthenticationController {

    def verifyCredentials() {
        def json = request.JSON

        Hasher hasher = (Hasher) new YubiHSMHasher()

        json.auth.factors.each {
            if (it.type == 'password') {
                def auth = new PasswordFactor("authenticate", it, params.id)
                if (!auth.authenticate(hasher)) {
                    def response = [action: "auth", status: false]
                    render response as JSON
                    return
                }
            }
        }
        def b = [action: "auth", status: true]
        render b as JSON
    }
}
