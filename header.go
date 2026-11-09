package eet

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	uuidSize          = 16
	uuidVersionByte   = 6
	uuidVariantByte   = 8
	uuidVersion4      = 0x40
	uuidVersionMask   = 0x0f
	uuidVariantRFC    = 0x80
	uuidVariantMask   = 0x3f
	securityIDEntropy = 16
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

func (h header) attrs() []attr {
	a := []attr{
		{name: "uuid_zpravy", value: h.uuid},
		{name: "dat_odesl", value: FormatDateTime(h.sentAt)},
		{name: "prvni_zaslani", value: formatBool(h.firstSending)},
	}
	if h.verification != nil {
		a = append(a, attr{name: "overeni", value: formatBool(*h.verification)})
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

type securityIDs struct {
	token     string
	signature string
	keyInfo   string
	tokenRef  string
	body      string
}

func newSecurityIDs() (securityIDs, error) {
	b := make([]byte, securityIDEntropy)
	if _, err := rand.Read(b); err != nil {
		return securityIDs{}, err
	}
	base := strings.ToUpper(hex.EncodeToString(b))
	return securityIDs{
		token:     "X509-" + base + "1",
		signature: "SIG-" + base + "2",
		keyInfo:   "KI-" + base + "3",
		tokenRef:  "STR-" + base + "4",
		body:      "id-" + base + "5",
	}, nil
}
