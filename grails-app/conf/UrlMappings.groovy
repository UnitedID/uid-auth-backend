class UrlMappings {

	static mappings = {

        "/api/credential/$id"(controller: "credential") {
            action = [POST:"add", DELETE: "revoke" ]
        }

        "/api/authenticate/$id"(controller: "authentication") {
            action = [POST: "verifyCredentials"]
        }

        //"/login/$action?/$id?(.${format})?"(controller: "login") {}
        //"/$controller/$action?/$id?(.${format})?" {}

        "500"(view:'/error')
	}
}
