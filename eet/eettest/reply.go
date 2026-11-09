package eettest

import (
	"time"

	"github.com/noona-hq/eet2-go-sdk/eet"
)

type replyKind int

const (
	replyAccept replyKind = iota
	replyReject
	replyUnavailable
)

const (
	temporaryErrorMessage = "Docasna technicka chyba zpracovani - odeslete prosim datovou zpravu pozdeji"
	unavailableBody       = "<html><body>Service Unavailable</body></html>"
)

type Reply struct {
	kind     replyKind
	code     int
	message  string
	warnings []eet.Warning
	delay    time.Duration
}

func Accept(warnings ...eet.Warning) Reply {
	return Reply{kind: replyAccept, warnings: warnings}
}

func Reject(code int, message string) Reply {
	return Reply{kind: replyReject, code: code, message: message}
}

func TemporaryError() Reply {
	return Reject(eet.CodeTemporary, temporaryErrorMessage)
}

func Unavailable() Reply {
	return Reply{kind: replyUnavailable}
}

func (r Reply) After(d time.Duration) Reply {
	delayed := r
	delayed.delay = d
	return delayed
}
