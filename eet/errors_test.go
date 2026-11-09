package eet

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestShouldResend(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "no error", err: nil, want: false},
		{name: "time limit exceeded", err: &TransportError{Err: context.DeadlineExceeded, Timeout: true}, want: true},
		{name: "network failure", err: &TransportError{Err: errors.New("connection refused")}, want: true},
		{name: "temporary technical error", err: &ResponseError{Code: CodeTemporary}, want: true},
		{name: "rejected message", err: &ResponseError{Code: CodeSchemaViolation}, want: false},
		{name: "verification result", err: &ResponseError{Code: CodeVerificationOK}, want: false},
		{name: "SOAP fault", err: &SOAPFault{Code: "soapenv:Server"}, want: true},
		{name: "HTTP error", err: &HTTPError{StatusCode: 503}, want: true},
		{name: "malformed response", err: fmt.Errorf("%w: truncated", ErrInvalidResponse), want: true},
		{name: "unverifiable acknowledgement", err: ErrInvalidSignature, want: true},
		{name: "unsigned acknowledgement", err: ErrResponseNotSigned, want: true},
		{name: "acknowledgement of another message", err: ErrResponseUUIDMismatch, want: true},
		{name: "invalid sale", err: ValidationErrors{{Field: "id_pokl"}}, want: false},
		{name: "expired certificate", err: ErrCertificateNotValid, want: false},
		{name: "message too large", err: ErrMessageTooLarge, want: false},
		{name: "message already sent", err: ErrMessageAlreadySent, want: false},
		{name: "wrapped rejection", err: fmt.Errorf("register: %w", &ResponseError{Code: CodeInvalidEIC}), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ShouldResend(tc.err); got != tc.want {
				t.Fatalf("ShouldResend(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestMessageUUID(t *testing.T) {
	t.Parallel()
	const uuid = "e23e5a5a-08d7-4a08-844d-2b6c6b60621d"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "transport error", err: &TransportError{Err: context.DeadlineExceeded, MessageUUID: uuid}, want: uuid},
		{name: "HTTP error", err: &HTTPError{StatusCode: 503, MessageUUID: uuid}, want: uuid},
		{name: "SOAP fault", err: &SOAPFault{Code: "soapenv:Server", MessageUUID: uuid}, want: uuid},
		{name: "rejected message", err: &ResponseError{Code: CodeSchemaViolation, MessageUUID: uuid}, want: uuid},
		{name: "wrapped", err: fmt.Errorf("register: %w", &TransportError{Err: context.Canceled, MessageUUID: uuid}), want: uuid},
		{name: "error before sending", err: ErrNoSigner},
		{name: "no error", err: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := MessageUUID(tc.err); got != tc.want {
				t.Fatalf("MessageUUID() = %q, want %q", got, tc.want)
			}
		})
	}
}
