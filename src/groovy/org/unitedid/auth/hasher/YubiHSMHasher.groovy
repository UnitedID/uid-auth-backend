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
    def loadTempKey(String nonce, int keyHandle, String aead) {
        return null  //To change body of implemented methods use File | Settings | File Templates.
    }
}
