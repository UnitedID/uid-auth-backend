package org.unitedid.auth.backend

import grails.gorm.dirty.checking.DirtyCheck
import grails.persistence.Entity
import org.bson.types.ObjectId

@Entity
@DirtyCheck
class CredentialStore {
    ObjectId id
    Date dateCreated
    Date lastUpdated
    Map credential

    static mapWith = "mongo"
}

