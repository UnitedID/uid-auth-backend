package org.unitedid.auth.hasher.impl

interface Hasher {
    def hmacSha1(int keyHandle, byte[] data)
    def random(int size)
    def validateHOTP(int keyHandle, String nonce, String aead, int counter, String userCode, int lookAhead)
    def validateTOTP(int keyHandle, String nonce, String aead, String userCode)
}
