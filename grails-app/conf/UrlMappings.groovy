class UrlMappings {

	static mappings = {
        "/credential/$id"(controller: "credential") {
            action = [POST:"add", PUT:"update", DELETE: "revoke" ]
        }

        "/authenticate/$id"(controller: "authentication") {
            action = [POST: "verifyCredentials"]
        }

        "500"(view:'/error')
	}
}
