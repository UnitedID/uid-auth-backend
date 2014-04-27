package org.unitedid.auth.backend
import grails.converters.JSON
import org.unitedid.auth.factors.PasswordFactor
import org.unitedid.auth.hasher.YubiHSMHasher
import org.unitedid.auth.hasher.impl.Hasher

class CredentialController {

    def add() {
        def json = request.JSON

        print json

        if (!json?.addCreds?.version || !json?.addCreds?.userId || !json?.addCreds?.factors) {
            throw new IllegalArgumentException("Bad JSON payload")
        }

        Hasher hasher = (Hasher) new YubiHSMHasher()

        json.addCreds.factors.each {
            print it
            if (it.type == 'password') {
                def credential = new PasswordFactor("addCred", it, params.id)
                if(!credential.addCredential(hasher)) {
                    def response = [action: "addCred", status: false]
                    render response as JSON
                    return
                }
            }
        }
        def response = [action: "addCred", status: true]
        render response as JSON
    }
    def update() {

    }

    def revoke() {

    }
}
