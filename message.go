package eet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const (
	TransactionIDHeader = "X-Global-Transaction-Id"

	contentTypeSOAP   = "text/xml; charset=utf-8"
	maxResponseSize   = 1 << 20
	errorBodyPreview  = 512
	htmlDoctypePrefix = "<!doctype html"
	htmlRootPrefix    = "<html"
)

type timeoutError interface {
	error
	Timeout() bool
}

type Message struct {
	UUID         string
	SentAt       time.Time
	FirstSending bool
	Verification bool
	Sale         Sale
	XML          []byte
	client       *Client
	sent         atomic.Bool
}

func (m *Message) Send(ctx context.Context) (*Response, error) {
	if !m.sent.CompareAndSwap(false, true) {
		return nil, ErrMessageAlreadySent
	}
	c := m.client
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(m.XML))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentTypeSOAP)
	req.Header.Set("SOAPAction", `"`+SOAPAction+`"`)

	res, err := c.http.Do(req)
	if err != nil {
		return nil, &TransportError{Err: err, Timeout: isTimeout(err)}
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize))
	if err != nil {
		return nil, &TransportError{Err: err, Timeout: isTimeout(err)}
	}
	txID := res.Header.Get(TransactionIDHeader)
	httpErr := &HTTPError{StatusCode: res.StatusCode, Body: preview(raw), TransactionID: txID}
	if !isXML(res.Header.Get("Content-Type"), raw) {
		return nil, httpErr
	}

	resp, err := c.parse(raw)
	if fault, ok := errors.AsType[*SOAPFault](err); ok {
		return nil, &SOAPFault{
			Code:          fault.Code,
			String:        fault.String,
			Actor:         fault.Actor,
			Detail:        fault.Detail,
			HTTPStatus:    res.StatusCode,
			TransactionID: txID,
		}
	}
	if resp == nil && res.StatusCode != http.StatusOK {
		return nil, httpErr
	}
	if resp == nil {
		return nil, err
	}
	resp.TransactionID = txID
	resp.Raw = raw
	if resp.Error != nil {
		resp.Error.TransactionID = txID
	}
	if err != nil {
		return resp, err
	}
	if resp.MessageUUID != "" && !strings.EqualFold(resp.MessageUUID, m.UUID) {
		return resp, ErrResponseUUIDMismatch
	}
	if resp.Error != nil && !(m.Verification && resp.Error.Code == CodeVerificationOK) {
		return resp, resp.Error
	}
	return resp, nil
}

func (c *Client) parse(raw []byte) (*Response, error) {
	if !c.verify {
		return parseUnverified(raw)
	}
	v, verr := verifyEnvelope(raw)
	if verr != nil {
		return parseUnsigned(raw, verr)
	}
	body, err := parseSignedBody(v.canonicalBody)
	if err != nil {
		return nil, err
	}
	resp, err := body.toResponse()
	if err != nil {
		return nil, err
	}
	resp.Signed = true
	resp.SigningCertificate = v.certificate
	if c.certCheck == nil {
		return resp, nil
	}
	if err := c.certCheck(v.certificate); err != nil {
		return resp, fmt.Errorf("%w: signing certificate rejected: %v", ErrInvalidSignature, err)
	}
	return resp, nil
}

func parseUnverified(raw []byte) (*Response, error) {
	body, err := parseEnvelopeBody(raw)
	if err != nil {
		return nil, err
	}
	return body.toResponse()
}

func parseUnsigned(raw []byte, verr error) (*Response, error) {
	resp, err := parseUnverified(raw)
	if err != nil {
		return nil, err
	}
	switch {
	case !errors.Is(verr, ErrUnsigned):
		return resp, verr
	case resp.Accepted():
		return resp, ErrResponseNotSigned
	default:
		return resp, nil
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	t, ok := errors.AsType[timeoutError](err)
	return ok && t.Timeout()
}

func isXML(contentType string, raw []byte) bool {
	if strings.Contains(strings.ToLower(contentType), "xml") {
		return true
	}
	lower := bytes.ToLower(bytes.TrimSpace(raw))
	return len(lower) > 0 && lower[0] == '<' && !bytes.HasPrefix(lower, []byte(htmlDoctypePrefix)) && !bytes.HasPrefix(lower, []byte(htmlRootPrefix))
}

func preview(raw []byte) string {
	return string(raw[:min(len(raw), errorBodyPreview)])
}
