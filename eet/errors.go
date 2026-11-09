package eet

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/noona-hq/eet2-go-sdk/internal/wssec"
)

var (
	ErrAmountOutOfRange     = errors.New("eet: amount must be greater than -100000000.00 and less than 100000000.00 CZK")
	ErrNotRSA               = errors.New("eet: the cash register certificate must contain an RSA key")
	ErrKeyMismatch          = errors.New("eet: private key does not match the certificate")
	ErrIncorrectPassword    = errors.New("eet: incorrect PKCS#12 password")
	ErrKeyNotExportable     = errors.New("eet: private key cannot be exported")
	ErrInvalidResponse      = errors.New("eet: invalid response")
	ErrUnsigned             = wssec.ErrUnsigned
	ErrInvalidSignature     = wssec.ErrInvalidSignature
	ErrTimeoutTooShort      = fmt.Errorf("eet: response time limit must be at least %s", MinTimeout)
	ErrMessageTooLarge      = fmt.Errorf("eet: message exceeds %d bytes", MaxMessageSize)
	ErrMessageAlreadySent   = errors.New("eet: message was already sent; prepare a new message for every attempt")
	ErrCertificateNotValid  = errors.New("eet: cash register certificate is not valid at the time of sending")
	ErrResponseNotSigned    = errors.New("eet: acknowledgement is not signed")
	ErrResponseUUIDMismatch = errors.New("eet: response uuid_zpravy does not match the sent message")
)

type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("eet: invalid %s: %s", e.Field, e.Reason)
}

type ValidationErrors []*ValidationError

func (e ValidationErrors) Error() string {
	msgs := make([]string, len(e))
	for i, v := range e {
		msgs[i] = v.Error()
	}
	return strings.Join(msgs, "; ")
}

func (e ValidationErrors) Unwrap() []error {
	errs := make([]error, len(e))
	for i, v := range e {
		errs[i] = v
	}
	return errs
}

type TransportError struct {
	Err         error
	Timeout     bool
	MessageUUID string
}

func (e *TransportError) Error() string {
	if e.Timeout {
		return "eet: response time limit exceeded: " + e.Err.Error()
	}
	return "eet: transport error: " + e.Err.Error()
}

func (e *TransportError) Unwrap() error {
	return e.Err
}

type HTTPError struct {
	StatusCode    int
	Body          string
	TransactionID string
	MessageUUID   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("eet: unexpected HTTP status %d", e.StatusCode)
}

type ResponseError struct {
	Code          int
	Message       string
	Test          bool
	MessageUUID   string
	RejectedAt    time.Time
	TransactionID string
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("eet: error %d: %s", e.Code, e.Message)
}

func (e *ResponseError) Temporary() bool {
	return e.Code < 0
}

type SOAPFault struct {
	Code          string
	String        string
	Actor         string
	Detail        string
	HTTPStatus    int
	TransactionID string
	MessageUUID   string
}

func (f *SOAPFault) Error() string {
	return fmt.Sprintf("eet: SOAP fault %s: %s", f.Code, f.String)
}

func ShouldResend(err error) bool {
	if err == nil {
		return false
	}
	if re, ok := errors.AsType[*ResponseError](err); ok {
		return re.Temporary()
	}
	if _, ok := errors.AsType[*ValidationError](err); ok {
		return false
	}
	for _, permanent := range []error{ErrCertificateNotValid, ErrMessageTooLarge, ErrMessageAlreadySent} {
		if errors.Is(err, permanent) {
			return false
		}
	}
	return true
}
