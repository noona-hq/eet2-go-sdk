package eet

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"time"

	"github.com/noona-hq/eet2-go-sdk/internal/wssec"
)

const (
	uuidSize        = 16
	uuidVersionByte = 6
	uuidVariantByte = 8
	uuidVersion4    = 0x40
	uuidVersionMask = 0x0f
	uuidVariantRFC  = 0x80
	uuidVariantMask = 0x3f
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	pokPattern  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}-[0-9a-fA-F]{2}$`)
)

type header struct {
	uuid         string
	sentAt       time.Time
	firstSending bool
	verification *bool
}

func (h header) attrs() []wssec.Attr {
	a := []wssec.Attr{
		{Name: "uuid_zpravy", Value: h.uuid},
		{Name: "dat_odesl", Value: FormatDateTime(h.sentAt)},
		{Name: "prvni_zaslani", Value: formatBool(h.firstSending)},
	}
	if h.verification != nil {
		a = append(a, wssec.Attr{Name: "overeni", Value: formatBool(*h.verification)})
	}
	return a
}

func (h header) validate() error {
	if !uuidPattern.MatchString(h.uuid) {
		return &ValidationError{Field: "uuid_zpravy", Reason: fmt.Sprintf("%q is not a valid UUID", h.uuid)}
	}
	if err := validDateTime(h.sentAt); err != nil {
		return &ValidationError{Field: "dat_odesl", Reason: err.Error()}
	}
	return nil
}

func newUUID() (string, error) {
	var b [uuidSize]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[uuidVersionByte] = b[uuidVersionByte]&uuidVersionMask | uuidVersion4
	b[uuidVariantByte] = b[uuidVariantByte]&uuidVariantMask | uuidVariantRFC
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
