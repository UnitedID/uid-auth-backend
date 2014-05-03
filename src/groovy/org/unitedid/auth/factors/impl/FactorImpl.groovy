package org.unitedid.auth.factors.impl

import org.unitedid.auth.hasher.impl.Hasher

interface FactorImpl {
    def addCredential(Hasher hasher)
    def authenticate(Hasher hasher)
}
