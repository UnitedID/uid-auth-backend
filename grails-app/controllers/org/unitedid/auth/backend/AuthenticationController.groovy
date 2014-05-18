package org.unitedid.auth.backend
import grails.converters.JSON
import grails.plugin.springsecurity.annotation.Secured
import grails.util.Holders
import org.unitedid.auth.hasher.YubiHSMHasher
import org.unitedid.auth.hasher.impl.Hasher

class AuthenticationController {

    static def config = Holders.config
    def credentialType = config.auth.credential.types

    @Secured(["hasAnyRole('ROLE_ADMIN', 'ROLE_AUTH_CRED')"])
    def verifyCredentials() {
        def json = request.JSON

        Hasher hasher = (Hasher) new YubiHSMHasher()

        def fail = 0
        json.auth.factors.each {
            def credential
            if (credentialType.containsKey(it.type)) {
                credential = this.class.classLoader
                        .loadClass(credentialType[it.type])
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
