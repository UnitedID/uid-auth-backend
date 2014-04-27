package org.unitedid.auth.backend
import org.bson.types.ObjectId

class CredentialStore {
    ObjectId id
    Date dateCreated
    Date lastUpdated
    Map credential

    static mapWith = "mongo"
    //static embedded = ['credential']


/*    static mapping = {
        collection 'credentialStore'
    }*/

    /*static constraints = {
        credential nullable: true
    } */
}

/*class Credential {
    String credentialId = new ObjectId().toString()
    String status
    String version = 1
    String type = "unknown"
}

class OATH extends Credential {
    Integer keyHandle
    String aead
    String digits
    Integer counter = 0
    String nonce
} */

class PasswordCredential  {
    String credentialId
    String status
    Integer version = 1
    String derived_key
    Integer iterations
    Integer keyHandle
    String salt
    String nonce
    String kdf
    String type = "password"
    String userId
    String H1

    static transients = ['H1']

    def beforeInsert() {
        this.derived_key = this.H1
    }

}
