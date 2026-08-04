package model

import "strings"

// MultipleErrors is an error type that supports multiple errors
type MultipleErrors []error

func (e MultipleErrors) Error() string {
	if len(e) == 1 {
		return e[0].Error()
	}

	var msg strings.Builder
	msg.WriteString("multiple errors:")
	for _, err := range e {
		msg.WriteString("\n" + err.Error())
	}
	return msg.String()
}
