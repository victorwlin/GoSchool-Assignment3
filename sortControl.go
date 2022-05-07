package main

func (f *friendList) sortControl(sortType string) {
	for i := 1; i < f.size; i++ {
		// copy
		copy := f.traverse(i)

		// loop over sorted and shift to right as necessary
		sorted := i
		switch sortType {

		// friend name
		case "friend":
			for sorted > 0 && copy.Name < f.traverse(sorted-1).Name {
				f.traverse(sorted - 1).next = f.traverse(sorted + 1)
				copy.next = f.traverse(sorted - 1)

				if sorted <= 1 {
					f.head = copy
				} else {
					f.traverse(sorted - 2).next = copy
				}

				sorted--
			}

		// group
		case "group":
			for sorted > 0 && copy.Group < f.traverse(sorted-1).Group {
				f.traverse(sorted - 1).next = f.traverse(sorted + 1)
				copy.next = f.traverse(sorted - 1)

				if sorted <= 1 {
					f.head = copy
				} else {
					f.traverse(sorted - 2).next = copy
				}

				sorted--
			}

		// date of last contact
		case "lastcontact":
			for sorted > 0 && copy.LastContact.top.date.After(f.traverse(sorted-1).LastContact.top.date) {
				f.traverse(sorted - 1).next = f.traverse(sorted + 1)
				copy.next = f.traverse(sorted - 1)

				if sorted <= 1 {
					f.head = copy
				} else {
					f.traverse(sorted - 2).next = copy
				}

				sorted--
			}

		// desired frequency of contact
		case "desiredfreq":
			for sorted > 0 && copy.DesiredFreqOfContact < f.traverse(sorted-1).DesiredFreqOfContact {
				f.traverse(sorted - 1).next = f.traverse(sorted + 1)
				copy.next = f.traverse(sorted - 1)

				if sorted <= 1 {
					f.head = copy
				} else {
					f.traverse(sorted - 2).next = copy
				}

				sorted--
			}

		// recommended date of next contact
		case "recdate":
			for sorted > 0 && copy.LastContact.top.date.AddDate(0, 0, copy.DesiredFreqOfContact).Before(f.traverse(sorted-1).LastContact.top.date.AddDate(0, 0, f.traverse(sorted-1).DesiredFreqOfContact)) {
				f.traverse(sorted - 1).next = f.traverse(sorted + 1)
				copy.next = f.traverse(sorted - 1)

				if sorted <= 1 {
					f.head = copy
				} else {
					f.traverse(sorted - 2).next = copy
				}

				sorted--
			}

		default:
			return
		}
	}

}
