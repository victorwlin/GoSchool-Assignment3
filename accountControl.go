package main

import (
	"net/http"
)

func accountManagement(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	tpl.ExecuteTemplate(res, "accountmanagement.gohtml", user.profileName)
}
