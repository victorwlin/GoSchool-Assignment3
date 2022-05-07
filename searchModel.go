package main

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func (f *friendList) seqSearch(friendName string) (friend *friend, i int) {

	i = 0
	currentFriend := f.head
	for {
		if currentFriend.Name == friendName {
			return currentFriend, i
		} else if currentFriend.next == nil {
			fmt.Println(errors.New("Friend not found."))
			return currentFriend.next, -1
		} else {
			currentFriend = currentFriend.next
			i++
		}
	}
}

func deleteFriend(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	friend := req.FormValue("friend")
	_, i := user.friends.seqSearch(friend)
	user.friends.removeFriend(i)

	http.Redirect(res, req, "/friends/", http.StatusSeeOther)
}

func editFriendDetails(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	friend := req.FormValue("friend")
	friendNode, _ := user.friends.seqSearch(friend)

	if req.Method == http.MethodPost {
		newFriendName := req.FormValue("newFriendName")
		newGroup := req.FormValue("newGroup")
		newLastContact := req.FormValue("newLastContact")
		newDesiredFreq := req.FormValue("newDesiredFreq")

		if newFriendName != "" {
			if user.friends.doesFriendExist(newFriendName) {
				http.Error(res, "User does not exist.", http.StatusUnauthorized)
				return
			}

			friendNode.Name = newFriendName
		}

		if newGroup != "" {
			friendNode.Group = newGroup
		}

		if newLastContact != "" {
			friendNode.LastContact.top.date, _ = time.Parse("2006-01-02", newLastContact)
		}

		if newDesiredFreq != "" {
			friendNode.DesiredFreqOfContact, _ = strconv.Atoi(newDesiredFreq)
		}

		http.Redirect(res, req, "/search/?friend="+friendNode.Name, http.StatusSeeOther)
	}

	tpl.ExecuteTemplate(res, "editfrienddetails.gohtml", user.friends.makeSearchStruct(friendNode, user))
}
