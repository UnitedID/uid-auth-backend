import org.unitedid.auth.Role
//import org.unitedid.auth.backend.Password

class BootStrap {

    def init = { servletContext ->
        // Create default roles and admin user if the database has not been initialized
        if (Role.count() == 0) {
            ['ROLE_ADMIN', 'ROLE_ADD_CRED', 'ROLE_REVOKE_CRED', 'ROLE_AUTH_CRED'].each {
                new Role(authority: it).save(flush: true)
            }
        }
        // For now users have to be created using the grails console until I've got grails security ui
        // working properly with mongodb as backend.
        /*
        if (User.count() == 0) {
            def role = Role.findByAuthority('ROLE_ADMIN')
            new User(username: 'admin', password: 'password', authorities: [role]).save(flush: true)
        }
        */
    }
    def destroy = {
    }
}
