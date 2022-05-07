package main

import (
	"fmt"
	"time"
)

type dateNode struct {
	date time.Time
	last *dateNode
}

type stack struct {
	top  *dateNode
	size int
}

func (s *stack) push(date time.Time) {
	newDate := &dateNode{
		date: date,
		last: nil,
	}

	if s.top == nil {
		s.top = newDate
	} else {
		newDate.last = s.top
		s.top = newDate
	}
	s.size++
}

func (s *stack) printStack() {
	if s.top == nil {
		fmt.Println("No dates found")
	}

	currentDate := s.top
	for {
		if s.size == 1 {
			fmt.Printf("%v - Date of Last Contact\n", currentDate.date.Format("02 Jan 2006"))
			break
		} else if currentDate == s.top {
			fmt.Printf("%v - Date of Last Contact\n", currentDate.date.Format("02 Jan 2006"))
		} else if currentDate.last == nil {
			fmt.Println(currentDate.date.Format("02 Jan 2006"))
			break
		} else {
			fmt.Println(currentDate.date.Format("02 Jan 2006"))
		}
		currentDate = currentDate.last
	}
}
