package main

import (
	"net/http"
	"time"
)

func searchControl(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	friend := req.FormValue("friend")
	friendNode, _ := user.friends.seqSearch(friend)

	if req.Method == http.MethodPost {
		newLastContact := req.FormValue("newLastContact")

		// check if fields have been filled out
		if newLastContact == "" {

			http.Error(res, "Field must not be blank.", http.StatusUnauthorized)
			return

		} else {

			date, _ := time.Parse("2006-01-02", newLastContact)
			friendNode.LastContact.push(date)

		}
	}

	tpl.ExecuteTemplate(res, "search.gohtml", user.friends.makeSearchStruct(friendNode, user))
}
