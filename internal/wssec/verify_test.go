package wssec

import (
	"bytes"
	"errors"
	"regexp"
	"testing"

	"github.com/noona-hq/eet2-go-sdk/internal/fixtures"
)

const playgroundSigner = "NEOSTRE - playground prostredi EET"

var signatureValuePattern = regexp.MustCompile(`<ds:SignatureValue>.`)

func TestVerify(t *testing.T) {
	t.Parallel()
	sample := fixtures.SampleRequest(fixtures.EICLegalEntity)
	for _, tc := range []struct {
		name       string
		raw        []byte
		wantSigner string
		wantErr    error
	}{
		{name: "official sample legal entity", raw: sample, wantSigner: fixtures.EICLegalEntity},
		{name: "official sample VCP", raw: fixtures.SampleRequest(fixtures.EICVCP), wantSigner: fixtures.EICVCP},
		{name: "official sample natural person", raw: fixtures.SampleRequest(fixtures.EICNaturalPerson), wantSigner: fixtures.EICNaturalPerson},
		{name: "playground acknowledgement", raw: fixtures.PlaygroundResponse(fixtures.ResponseSend), wantSigner: playgroundSigner},
		{name: "playground acknowledgement with warnings", raw: fixtures.PlaygroundResponse(fixtures.ResponseWarnings), wantSigner: playgroundSigner},
		{name: "unsigned error response", raw: fixtures.PlaygroundResponse(fixtures.ResponseVerify), wantErr: ErrUnsigned},
		{name: "tampered body", raw: bytes.Replace(sample, []byte(`celk_trzba="`), []byte(`celk_trzba="1`), 1), wantErr: ErrInvalidSignature},
		{name: "tampered signature value", raw: signatureValuePattern.ReplaceAll(sample, []byte("<ds:SignatureValue>A")), wantErr: ErrInvalidSignature},
		{name: "signature references another element", raw: bytes.Replace(sample, []byte(`<soapenv:Body wsu:Id="id-`), []byte(`<soapenv:Body wsu:Id="other-`), 1), wantErr: ErrInvalidSignature},
		{name: "not a SOAP envelope", raw: []byte("<html/>"), wantErr: ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := Verify(tc.raw)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && v.Certificate.Subject.CommonName != tc.wantSigner {
				t.Fatalf("signed by %q, want %q", v.Certificate.Subject.CommonName, tc.wantSigner)
			}
		})
	}
}
