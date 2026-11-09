package eet

import (
	"bytes"
	"errors"
	"regexp"
	"testing"
)

var signatureValuePattern = regexp.MustCompile(`<ds:SignatureValue>.`)

func TestVerifyEnvelope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		raw        func(t *testing.T) []byte
		wantSigner string
		wantErr    error
	}{
		{name: "official sample CZ00000019", raw: testdataFile("CZ00000019.eet.v4.req.xml"), wantSigner: "CZ00000019"},
		{name: "official sample CZ683555118", raw: testdataFile("CZ683555118.eet.v4.req.xml"), wantSigner: "CZ683555118"},
		{name: "official sample CZ8551015704", raw: testdataFile("CZ8551015704.eet.v4.req.xml"), wantSigner: "CZ8551015704"},
		{name: "playground acknowledgement", raw: testdataFile("playground-response-send.xml"), wantSigner: "NEOSTRE - playground prostredi EET"},
		{name: "playground acknowledgement with warnings", raw: testdataFile("playground-response-warnings.xml"), wantSigner: "NEOSTRE - playground prostredi EET"},
		{name: "unsigned error response", raw: testdataFile("playground-response-verify.xml"), wantErr: ErrUnsigned},
		{name: "tampered body", raw: func(t *testing.T) []byte {
			return bytes.Replace(readTestdata(t, "CZ00000019.eet.v4.req.xml"), []byte(`celk_trzba="`), []byte(`celk_trzba="1`), 1)
		}, wantErr: ErrInvalidSignature},
		{name: "tampered signature value", raw: func(t *testing.T) []byte {
			return signatureValuePattern.ReplaceAll(readTestdata(t, "CZ00000019.eet.v4.req.xml"), []byte("<ds:SignatureValue>A"))
		}, wantErr: ErrInvalidSignature},
		{name: "signature references another element", raw: func(t *testing.T) []byte {
			return bytes.Replace(readTestdata(t, "CZ00000019.eet.v4.req.xml"), []byte(`<soapenv:Body wsu:Id="id-`), []byte(`<soapenv:Body wsu:Id="other-`), 1)
		}, wantErr: ErrInvalidSignature},
		{name: "not a SOAP envelope", raw: func(*testing.T) []byte { return []byte("<html/>") }, wantErr: ErrInvalidResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := verifyEnvelope(tc.raw(t))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && v.certificate.Subject.CommonName != tc.wantSigner {
				t.Fatalf("signed by %q, want %q", v.certificate.Subject.CommonName, tc.wantSigner)
			}
		})
	}
}

func testdataFile(name string) func(*testing.T) []byte {
	return func(t *testing.T) []byte { return readTestdata(t, name) }
}
