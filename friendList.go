package main

type friend struct {
	Name                 string
	Group                string
	LastContact          *stack
	DesiredFreqOfContact int
	next                 *friend
}

type friendList struct {
	head *friend
	size int
}

// create struct for display
type friendRender struct {
	Name                 string
	Group                string
	LastContact          string
	DesiredFreqOfContact int
	RecDateOfNextContact string
}

// create struct for search display
type searchRender struct {
	Name                 string
	Group                string
	HistoryOfContact     []string
	DesiredFreqOfContact int
	RecDateOfNextContact string
	LastContact          string
	AvailableGroups      []string
}

func (f *friendList) addFriend(name string, group string, lastContact *stack, desiredFreqOfContact int) {
	newFriend := &friend{
		Name:                 name,
		Group:                group,
		LastContact:          lastContact,
		DesiredFreqOfContact: desiredFreqOfContact,
		next:                 nil,
	}

	if f.head == nil {
		f.head = newFriend
	} else {
		currentFriend := f.head

		// traversal
		for currentFriend.next != nil {
			currentFriend = currentFriend.next
		}

		currentFriend.next = newFriend
	}

	f.size++
}

func (f *friendList) removeFriend(i int) {
	if i == 0 {
		f.head = f.head.next
	} else {
		currentFriend := f.head
		prevFriend := f.head
		for index := 0; index < i; index++ {
			prevFriend = currentFriend
			currentFriend = currentFriend.next
		}
		prevFriend.next = currentFriend.next
	}
	f.size--
}

func (f *friendList) traverse(index int) (friend *friend) {
	currentFriend := f.head
	for i := 0; i < index; i++ {
		currentFriend = currentFriend.next
	}
	return currentFriend
}

func (f *friendList) makeFriendsSlice() (friendsSlice []friendRender) {

	currentFriend := f.head
	for {
		insertFriend := friendRender{}
		if currentFriend == nil {

			return []friendRender{}

		} else {
			insertFriend = friendRender{
				Name:                 currentFriend.Name,
				Group:                currentFriend.Group,
				LastContact:          currentFriend.LastContact.top.date.Format("02 Jan 2006"),
				DesiredFreqOfContact: currentFriend.DesiredFreqOfContact,
				RecDateOfNextContact: currentFriend.LastContact.top.date.AddDate(0, 0, currentFriend.DesiredFreqOfContact).Format("02 Jan 2006"),
			}
		}

		friendsSlice = append(friendsSlice, insertFriend)

		if currentFriend.next == nil {
			break
		} else {
			currentFriend = currentFriend.next
		}
	}

	return friendsSlice
}

func (f *friendList) doesFriendExist(friendname string) bool {
	currentFriend := f.head
	for {
		if currentFriend.Name == friendname {
			return true
		}

		if currentFriend.next == nil {
			break
		} else {
			currentFriend = currentFriend.next
		}
	}

	return false
}

func (f *friendList) makeSearchStruct(friend *friend, user *userProfile) (searchStruct searchRender) {
	// create slice of dates contacted
	dateHistory := []string{}
	currentDate := friend.LastContact.top
	for currentDate != nil {
		dateHistory = append(dateHistory, currentDate.date.Format("02 Jan 2006"))
		currentDate = currentDate.last
	}

	lastContact := friend.LastContact.top.date.Format("02 Jan 2006")

	searchStruct = searchRender{
		Name:                 friend.Name,
		Group:                friend.Group,
		HistoryOfContact:     dateHistory,
		DesiredFreqOfContact: friend.DesiredFreqOfContact,
		RecDateOfNextContact: friend.LastContact.top.date.AddDate(0, 0, friend.DesiredFreqOfContact).Format("02 Jan 2006"),
		LastContact:          lastContact,
		AvailableGroups:      user.groups,
	}

	return searchStruct
}
