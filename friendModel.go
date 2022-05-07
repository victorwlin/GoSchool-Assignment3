package main

import (
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"
)

func addFriendToList(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	if req.Method == http.MethodPost {
		friendname := req.FormValue("friendname")
		group := req.FormValue("group")
		lastcontact := req.FormValue("lastcontact")
		desiredfreq := req.FormValue("desiredfreq")

		// check if fields have been filled out
		if friendname == "" || group == "" || desiredfreq == "" || lastcontact == "" {

			http.Error(res, "All fields must be filled out.", http.StatusUnauthorized)
			return

		} else {

			// check if friend exists
			if user.friends.doesFriendExist(friendname) {
				http.Error(res, "Friend already exists.", http.StatusUnauthorized)
				return
			}

			// conversions
			desiredfreqInt, _ := strconv.Atoi(desiredfreq)
			date, _ := time.Parse("2006-01-02", lastcontact)

			user.friends.addFriend(friendname, group, &stack{&dateNode{date, nil}, 0}, desiredfreqInt)

			http.Redirect(res, req, "/friends/", http.StatusSeeOther)

		}
	}

	tpl.ExecuteTemplate(res, "addfriend.gohtml", user.groups)
}

func addGroup(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	if req.Method == http.MethodPost {
		group := req.FormValue("group")

		if group == "" {

			http.Error(res, "All fields must be filled out.", http.StatusUnauthorized)
			return

		} else {

			// check if group exists
			exists := false
			for _, v := range user.groups {
				if v == group {
					exists = true
				}
			}

			if !exists {
				user.groups = append(user.groups, group)

				http.Redirect(res, req, "/friends/", http.StatusSeeOther)

			} else {
				http.Error(res, "Group already exists.", http.StatusUnauthorized)
				return
			}
		}

	}

	tpl.ExecuteTemplate(res, "addgroup.gohtml", nil)
}

func editExistingGroup(res http.ResponseWriter, req *http.Request) {
	user := getUser(res, req)

	if req.Method == http.MethodPost {
		group := req.FormValue("group")
		newgroup := req.FormValue("newgroup")

		if group == "" || newgroup == "" {

			http.Error(res, "All fields must be filled out.", http.StatusUnauthorized)
			return

		} else {

			runtime.GOMAXPROCS(2)
			var wg sync.WaitGroup
			wg.Add(2)

			// update all friends that are part of the changed group
			go func() {
				defer wg.Done()

				currentFriend := user.friends.head
				for {
					if currentFriend.Group == group {
						currentFriend.Group = newgroup
					}

					if currentFriend.next == nil {
						break
					} else {
						currentFriend = currentFriend.next
					}
				}
			}()

			// change group in the group slice
			go func() {
				defer wg.Done()

				for i, v := range user.groups {
					if v == group {
						user.groups[i] = newgroup
					}
				}
			}()

			wg.Wait()

			http.Redirect(res, req, "/friends/", http.StatusSeeOther)
		}
	}

	tpl.ExecuteTemplate(res, "editgroup.gohtml", user.groups)

}

func deleteGroup(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	user := getUser(res, req)

	if req.Method == http.MethodPost {
		group := req.FormValue("group")

		if group == "" {
			http.Error(res, "All fields must be filled out.", http.StatusUnauthorized)
			return
		} else {
			runtime.GOMAXPROCS(2)
			var wg sync.WaitGroup
			wg.Add(2)

			// delete all friends in group
			go func() {
				defer wg.Done()

				// identify all occurences
				deleteList := []int{}
				currentFriend := user.friends.head
				for index := 0; index < user.friends.size; index++ {
					if currentFriend.Group == group {
						deleteList = append(deleteList, index)
					}
					currentFriend = currentFriend.next
				}

				// delete friends
				for i, v := range deleteList {
					user.friends.removeFriend(v - i)
				}
			}()

			// delete group from group slice
			go func() {
				defer wg.Done()

				// identify group
				var index int
				for i, v := range user.groups {
					if v == group {
						index = i
						break
					}
				}

				copy(user.groups[index:], user.groups[index+1:])
				user.groups = user.groups[:len(user.groups)-1]
			}()

			wg.Wait()

			http.Redirect(res, req, "/friends/", http.StatusSeeOther)
		}
	}

	tpl.ExecuteTemplate(res, "deletegroup.gohtml", user.groups)
}
