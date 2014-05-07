package org.unitedid.auth.factors
import com.yubico.client.v2.YubicoClient
import grails.util.Holders
import org.unitedid.auth.backend.CredentialStore
import org.unitedid.auth.factors.impl.FactorImpl
import org.unitedid.auth.hasher.impl.Hasher

import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

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

        def yubikeyResponse = verifyYubiKeyOtp()
        if (yubikeyResponse.status == "OK") {
            calculatePublicIdHash(yubikeyResponse.publicId)

            if (publicIdHash == credentialStore.credential.publicIdHash) {
                return true
            }
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

        print response

        if (response) {
            switch (response.getStatus().toString()) {
                case "OK":
                    def publicId = YubicoClient.getPublicId(userCode)
                    return [publicId: publicId, status: "OK"]
                    break
                case "BAD_OTP":
                    return [publicId: null, status: "BAD_OTP"]
                    break
                case "REPLAYED_OTP":
                    def publicId = YubicoClient.getPublicId(otp)
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
