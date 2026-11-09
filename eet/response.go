package eet

import (
	"bytes"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	CodeVerificationOK     = 0
	CodeTemporary          = -1
	CodeInvalidXMLEncoding = 2
	CodeSchemaViolation    = 3
	CodeInvalidSignature   = 4
	CodeInvalidEIC         = 6
	CodeMessageTooLarge    = 7
	CodeNotProcessed       = 8

	minErrorCode   = -999
	maxErrorCode   = 999
	minWarningCode = 1
	maxWarningCode = 999
	maxWarnings    = 10
)

type Response struct {
	MessageUUID        string
	ReceivedAt         time.Time
	POK                string
	Test               bool
	Error              *ResponseError
	Warnings           []Warning
	TransactionID      string
	Signed             bool
	SigningCertificate *x509.Certificate
	Raw                []byte
}

func (r *Response) Accepted() bool {
	return r.POK != ""
}

func (r *Response) VerificationSucceeded() bool {
	return r.Error != nil && r.Error.Code == CodeVerificationOK
}

type xmlBody struct {
	Odpoved *xmlOdpoved `xml:"http://fs.gov.cz/eet/schema/v4 Odpoved"`
	Fault   *xmlFault   `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`
}

type xmlEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    *xmlBody `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
}

type xmlSignedBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	xmlBody
}

type xmlOdpoved struct {
	Hlavicka struct {
		UUID     string `xml:"uuid_zpravy,attr"`
		DatPrij  string `xml:"dat_prij,attr"`
		DatOdmit string `xml:"dat_odmit,attr"`
	} `xml:"http://fs.gov.cz/eet/schema/v4 Hlavicka"`
	Potvrzeni *struct {
		POK  string `xml:"pok,attr"`
		Test string `xml:"test,attr"`
	} `xml:"http://fs.gov.cz/eet/schema/v4 Potvrzeni"`
	Chyba *struct {
		Kod  string `xml:"kod,attr"`
		Test string `xml:"test,attr"`
		Text string `xml:",chardata"`
	} `xml:"http://fs.gov.cz/eet/schema/v4 Chyba"`
	Varovani []struct {
		Kod  string `xml:"kod_varov,attr"`
		Text string `xml:",chardata"`
	} `xml:"http://fs.gov.cz/eet/schema/v4 Varovani"`
}

type xmlFault struct {
	Code   string `xml:"faultcode"`
	String string `xml:"faultstring"`
	Actor  string `xml:"faultactor"`
	Detail struct {
		Inner string `xml:",innerxml"`
	} `xml:"detail"`
}

func parseEnvelopeBody(raw []byte) (*xmlBody, error) {
	var env xmlEnvelope
	if err := xml.NewDecoder(bytes.NewReader(raw)).Decode(&env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if env.Body == nil {
		return nil, fmt.Errorf("%w: missing SOAP Body", ErrInvalidResponse)
	}
	return env.Body, nil
}

func parseSignedBody(canonicalBody []byte) (*xmlBody, error) {
	var body xmlSignedBody
	if err := xml.Unmarshal(canonicalBody, &body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	return &body.xmlBody, nil
}

func (b *xmlBody) toResponse() (*Response, error) {
	if b.Fault != nil {
		return nil, &SOAPFault{
			Code:   strings.TrimSpace(b.Fault.Code),
			String: strings.TrimSpace(b.Fault.String),
			Actor:  strings.TrimSpace(b.Fault.Actor),
			Detail: strings.TrimSpace(b.Fault.Detail.Inner),
		}
	}
	o := b.Odpoved
	if o == nil {
		return nil, fmt.Errorf("%w: missing Odpoved", ErrInvalidResponse)
	}
	if o.Hlavicka.UUID != "" && !uuidPattern.MatchString(o.Hlavicka.UUID) {
		return nil, fmt.Errorf("%w: uuid_zpravy %q", ErrInvalidResponse, o.Hlavicka.UUID)
	}
	receivedAt, err := parseOptionalDateTime(o.Hlavicka.DatPrij)
	if err != nil {
		return nil, fmt.Errorf("%w: dat_prij: %v", ErrInvalidResponse, err)
	}
	rejectedAt, err := parseOptionalDateTime(o.Hlavicka.DatOdmit)
	if err != nil {
		return nil, fmt.Errorf("%w: dat_odmit: %v", ErrInvalidResponse, err)
	}
	warnings, err := o.warnings()
	if err != nil {
		return nil, err
	}
	r := &Response{MessageUUID: o.Hlavicka.UUID, ReceivedAt: receivedAt, Warnings: warnings}
	switch {
	case o.Potvrzeni != nil && o.Chyba != nil:
		return nil, fmt.Errorf("%w: both Potvrzeni and Chyba present", ErrInvalidResponse)
	case o.Potvrzeni != nil:
		if !pokPattern.MatchString(o.Potvrzeni.POK) {
			return nil, fmt.Errorf("%w: pok %q", ErrInvalidResponse, o.Potvrzeni.POK)
		}
		test, err := parseOptionalBool(o.Potvrzeni.Test)
		if err != nil {
			return nil, fmt.Errorf("%w: test: %v", ErrInvalidResponse, err)
		}
		r.POK = o.Potvrzeni.POK
		r.Test = test
	case o.Chyba != nil:
		code, err := strconv.Atoi(strings.TrimSpace(o.Chyba.Kod))
		if err != nil || code < minErrorCode || code > maxErrorCode {
			return nil, fmt.Errorf("%w: kod %q", ErrInvalidResponse, o.Chyba.Kod)
		}
		test, err := parseOptionalBool(o.Chyba.Test)
		if err != nil {
			return nil, fmt.Errorf("%w: test: %v", ErrInvalidResponse, err)
		}
		r.Test = test
		r.Error = &ResponseError{
			Code:        code,
			Message:     normalizeText(o.Chyba.Text),
			Test:        test,
			MessageUUID: r.MessageUUID,
			RejectedAt:  rejectedAt,
		}
	default:
		return nil, fmt.Errorf("%w: neither Potvrzeni nor Chyba present", ErrInvalidResponse)
	}
	return r, nil
}

func (o *xmlOdpoved) warnings() ([]Warning, error) {
	if len(o.Varovani) > maxWarnings {
		return nil, fmt.Errorf("%w: %d warnings, at most %d allowed", ErrInvalidResponse, len(o.Varovani), maxWarnings)
	}
	var w []Warning
	for _, v := range o.Varovani {
		code, err := strconv.Atoi(strings.TrimSpace(v.Kod))
		if err != nil || code < minWarningCode || code > maxWarningCode {
			return nil, fmt.Errorf("%w: kod_varov %q", ErrInvalidResponse, v.Kod)
		}
		w = append(w, Warning{Code: WarningCode(code), Message: normalizeText(v.Text)})
	}
	return w, nil
}

func normalizeText(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func parseOptionalBool(s string) (bool, error) {
	switch strings.TrimSpace(s) {
	case "", "false", "0":
		return false, nil
	case "true", "1":
		return true, nil
	}
	return false, fmt.Errorf("invalid boolean %q", s)
}
