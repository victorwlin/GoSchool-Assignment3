package main

import (
	"fmt"
	"net/http"
)

func editUser(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	oldName := user.profileName

	if req.Method == http.MethodPost {
		username := req.FormValue("username")

		if username == "" {

			http.Error(res, "All fields must be filled out.", http.StatusUnauthorized)
			return

		} else {

			// check if username exists
			exists := false
			for k := range users {
				if k == username {
					exists = true
				}
			}

			if !exists {
				// new entry into users map
				users[username] = &(*(users[user.profileName]))
				fmt.Println(users)
				// change profileName
				users[username].profileName = username

				// update mapSessions
				cookie, _ := req.Cookie("FriendTrackerCookie")
				mapSessions[cookie.Value] = username

				// delete old userProfile
				delete(users, oldName)

				http.Redirect(res, req, "/accountmanagement/", http.StatusSeeOther)

			} else {
				http.Error(res, "Username already exists.", http.StatusUnauthorized)
				return
			}
		}

	}

	tpl.ExecuteTemplate(res, "edituser.gohtml", nil)
}

func deleteUser(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	oldName := user.profileName

	delete(users, oldName)

	http.Redirect(res, req, "/logout/", http.StatusSeeOther)
}
