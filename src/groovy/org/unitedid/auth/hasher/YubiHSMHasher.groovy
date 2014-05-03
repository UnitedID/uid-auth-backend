package org.unitedid.auth.hasher
import grails.util.Holders
import org.unitedid.auth.hasher.impl.Hasher
import org.unitedid.yhsm.YubiHSM

class YubiHSMHasher implements Hasher {
    static def config = Holders.config

    YubiHSM hsm

    public YubiHSMHasher() {
        hsm = new YubiHSM((String) config.yhsm.device)
    }

    @Override
    def hmacSha1(int keyHandle, byte[] data) {
        return hsm.generateHMACSHA1(data, keyHandle, false)
    }

    @Override
    def random(int size) {
        return hsm.getRandom(size).encodeHex()
    }

    @Override
    def validateHOTP(int keyHandle, String nonce, String aead, int counter, String userCode, int lookAhead) {
        return hsm.validateOathHOTP(keyHandle, nonce, aead, counter, userCode, lookAhead)
    }

    @Override
    def validateTOTP(int keyHandle, String nonce, String aead, String userCode) {
        return hsm.validateOathTOTP(keyHandle, nonce, aead, userCode)
    }
}
