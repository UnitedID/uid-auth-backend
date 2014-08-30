package org.unitedid.auth.factors
import com.yubico.client.v2.YubicoClient
import grails.util.Holders
import groovy.util.logging.Log4j
import org.unitedid.auth.backend.CredentialStore
import org.unitedid.auth.factors.impl.FactorImpl
import org.unitedid.auth.hasher.impl.Hasher

import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@Log4j
class YubiKeyFactor implements FactorImpl {

    static def config = Holders.config

    String publicIdHash
    int iterations
    def status
    def type = "yubikey"
    String credentialId

    def userId
    String salt
    def credentialStore
    def jsonRequest
    def userCode


    def parseJson() {
        salt = jsonRequest.salt
        credentialId = jsonRequest.credentialId
        userCode = jsonRequest.userCode
    }

    @Override
    def addCredential(Hasher hasher) {
        parseJson()

        status = "active"
        iterations = (int) config.pbkdf2.iterations

        def yubikeyResponse = verifyYubiKeyOtp()
        if (yubikeyResponse.status == "OK") {
            calculatePublicIdHash(yubikeyResponse.publicId)

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

        credentialStore = CredentialStore.createCriteria().get {
            eq 'credential.credentialId', credentialId
        }

        if (!credentialStore || credentialStore.credential.status != "active") {
            return false
        }

        iterations = credentialStore.credential.iterations

        // TODO: temporary quick fix for OTP_REPLAYED issue when a user have got multiple Yubikeys attached to their account
        def tmpPublicId = YubicoClient.getPublicId(userCode)
        calculatePublicIdHash(tmpPublicId)

        if (publicIdHash == credentialStore.credential.publicIdHash && verifyYubiKeyOtp().status == "OK") {
            return true
        }

        return false
    }

    def calculatePublicIdHash(publicId) {
        String T1 = "Y" + userId + credentialId + publicId
        PBEKeySpec keySpec = new PBEKeySpec(T1.toCharArray(), salt.decodeHex(), iterations, 64 * 8)
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        SecretKey secretKey = keyFactory.generateSecret(keySpec)
        publicIdHash = secretKey.getEncoded().encodeHex()
    }

    def verifyYubiKeyOtp() {
        def client = YubicoClient.getClient()
        client.setClientId(4711)
        def response = client.verify(userCode)

        if (response) {
            switch (response.getStatus().toString()) {
                case "OK":
                    def publicId = YubicoClient.getPublicId(userCode)
                    log.debug("YubiKey OTP OK for credentialId " + credentialId)
                    return [publicId: publicId, status: "OK"]
                    break
                case "BAD_OTP":
                    log.debug("YubiKey BAD_OTP for credentialId " + credentialId)
                    return [publicId: null, status: "BAD_OTP"]
                    break
                case "REPLAYED_OTP":
                    def publicId = YubicoClient.getPublicId(userCode)
                    log.debug("YubiKey REPLAYED_OTP for credentialId " + credentialId)
                    return [publicId: publicId, status: "REPLAYED_OTP"]
                    break
            }

        }

        return [publicId: null, status: false]
    }

    public Map asMap() {
        this.class.declaredFields.findAll {
            it.modifiers == java.lang.reflect.Modifier.PRIVATE &&
                    it.name in ['publicIdHash',
                    'iterations',
                    'status',
                    'type',
                    'credentialId'
            ]
        }.collectEntries {
            [it.name, this[it.name]]
        }
    }
}
