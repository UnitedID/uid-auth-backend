package org.unitedid.auth

import org.bson.types.ObjectId

class Role {

    ObjectId id
	String authority

    static mapWith = "mongo"

	static mapping = {
		cache true
	}

	static constraints = {
		authority blank: false, unique: true
	}
}
