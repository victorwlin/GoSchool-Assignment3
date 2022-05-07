package main

import (
	"net/http"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

func getUser(res http.ResponseWriter, req *http.Request) (user *userProfile) {
	// get current session cookie
	cookie, err := req.Cookie("FriendTrackerCookie")

	// if cookie doesn't exist, redirect to login
	if err != nil {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	if _, ok := mapSessions[cookie.Value]; ok {
		username := mapSessions[cookie.Value]

		user = users[username]
	}

	return user
}

func alreadyLoggedIn(req *http.Request) bool {
	cookie, err := req.Cookie("FriendTrackerCookie")
	if err != nil {
		return false
	}

	username := mapSessions[cookie.Value]
	_, ok := users[username]

	return ok
}

func login(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/friends/", http.StatusSeeOther)
		return
	}

	// process form submission
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")

		// check if user exists using entered username
		user, ok := users[username]
		if !ok {
			http.Error(res, "User does not exist.", http.StatusUnauthorized)
			return
		}

		// check if password matches our records
		err := bcrypt.CompareHashAndPassword(user.password, []byte(password))
		if err != nil {
			http.Error(res, "Username and password do not match.", http.StatusForbidden)
			return
		}

		// create session
		id := uuid.NewV4()
		cookie := &http.Cookie{
			Name:  "FriendTrackerCookie",
			Value: id.String(),
			Path:  "/",
		}
		http.SetCookie(res, cookie)

		mapSessions[cookie.Value] = username

		http.Redirect(res, req, "/friends/", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(res, "login.gohtml", nil)
}

func signup(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/friends/", http.StatusSeeOther)
		return
	}

	// process form submission
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")

		if username == "" || password == "" {
			http.Error(res, "Both fields must contain values.", http.StatusForbidden)
			return
		} else {

			// check if username already exists
			if _, ok := users[username]; ok {
				http.Error(res, "Username already taken.", http.StatusForbidden)
				return
			}

			// create session
			id := uuid.NewV4()
			cookie := &http.Cookie{
				Name:  "FriendTrackerCookie",
				Value: id.String(),
				Path:  "/",
			}
			http.SetCookie(res, cookie)

			mapSessions[cookie.Value] = username

			// create password
			pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			if err != nil {
				http.Error(res, "Internal server error", http.StatusInternalServerError)
				return
			}

			// create user profile
			users[username] = &userProfile{
				profileName: username,
				password:    pw,
				groups:      []string{},
				friends:     &friendList{nil, 0},
			}

			http.Redirect(res, req, "/friends/", http.StatusSeeOther)
			return
		}
	}

	tpl.ExecuteTemplate(res, "signup.gohtml", nil)
}

func logout(res http.ResponseWriter, req *http.Request) {
	cookie, _ := req.Cookie("FriendTrackerCookie")

	// delete session
	delete(mapSessions, cookie.Value)

	// remove cookie
	cookie = &http.Cookie{
		Name:   "FriendTrackerCookie",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(res, cookie)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}
