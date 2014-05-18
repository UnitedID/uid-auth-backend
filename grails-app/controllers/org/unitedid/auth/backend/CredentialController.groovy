package org.unitedid.auth.backend
import grails.converters.JSON
import grails.plugin.springsecurity.annotation.Secured
import grails.util.Holders
import org.unitedid.auth.hasher.YubiHSMHasher
import org.unitedid.auth.hasher.impl.Hasher

class CredentialController {

    static def config = Holders.config
    def credentialType = config.auth.credential.types

    @Secured(["hasAnyRole('ROLE_ADMIN', 'ROLE_ADD_CRED')"])
    def add() {
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
                        .loadClass(credentialType[it.type])
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

    @Secured(["hasAnyRole('ROLE_ADMIN', 'ROLE_REVOKE_CRED')"])
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
