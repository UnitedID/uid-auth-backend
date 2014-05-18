package org.unitedid.auth

import org.bson.types.ObjectId

class User {

	transient springSecurityService

    ObjectId id
	String username
	String password
	boolean enabled = true
	boolean accountExpired
	boolean accountLocked
	boolean passwordExpired
    Set<Role> authorities

    static mapWith = "mongo"

	static transients = ['springSecurityService']

    static embedded = ['authorities']

	static constraints = {
		username blank: false, unique: true
		password blank: false
	}

	static mapping = {
		password column: '`password`'
	}

	def beforeInsert() {
		encodePassword()
	}

	def beforeUpdate() {
		if (isDirty('password')) {
			encodePassword()
		}
	}

	protected void encodePassword() {
		password = springSecurityService.encodePassword(password)
	}
}
