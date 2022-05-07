package main

import (
	"net/http"
)

func friendsControl(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	sortType := req.FormValue("sort")
	user.friends.sortControl(sortType)

	if req.Method == http.MethodPost {
		friend := req.FormValue("friend")

		// check if fields have been filled out
		if friend == "" {

			http.Error(res, "Search field must not be blank.", http.StatusUnauthorized)
			return

		} else {

			// check if friend exists
			friendNode, _ := user.friends.seqSearch(friend)
			if friendNode == nil {
				http.Error(res, "Friend does not exist.", http.StatusUnauthorized)
				return
			} else {
				http.Redirect(res, req, "/search/?friend="+friend, http.StatusSeeOther)
			}
		}
	}

	tpl.ExecuteTemplate(res, "friends.gohtml", user.friends.makeFriendsSlice())
}
