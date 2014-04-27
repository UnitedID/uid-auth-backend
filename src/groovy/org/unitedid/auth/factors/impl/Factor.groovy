package org.unitedid.auth.factors.impl

import org.unitedid.auth.hasher.impl.Hasher

interface Factor {
    def addCredential(Hasher hasher)
    def authenticate(Hasher hasher)
}
