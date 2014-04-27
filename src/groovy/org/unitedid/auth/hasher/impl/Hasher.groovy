package org.unitedid.auth.hasher.impl

interface Hasher {
    def hmacSha1(int keyHandle, byte[] data)
    def random(int size)
    def loadTempKey(String nonce, int keyHandle, String aead)
}
