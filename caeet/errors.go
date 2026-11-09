package caeet

import (
	"errors"
	"fmt"
)

var (
	ErrRejected        = errors.New("caeet: certificate request rejected")
	ErrUnexpectedState = errors.New("caeet: unexpected request state")
)

type APIError struct {
	StatusCode     int
	Code           int
	Message        string
	AdditionalInfo string
}

func (e *APIError) Error() string {
	if e.AdditionalInfo != "" {
		return fmt.Sprintf("caeet: HTTP %d: error %d: %s (%s)", e.StatusCode, e.Code, e.Message, e.AdditionalInfo)
	}
	return fmt.Sprintf("caeet: HTTP %d: error %d: %s", e.StatusCode, e.Code, e.Message)
}
