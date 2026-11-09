package eet

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

type opaqueKey struct {
	crypto.Signer
}

func pemBlock(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func TestParsePEM(t *testing.T) {
	t.Parallel()
	s := playgroundSigner(t, testEIC)
	other := playgroundSigner(t, "CZ683555118")
	key := s.Key().(*rsa.PrivateKey)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pemBlock(pemCertificate, s.Certificate().Raw)
	for _, tc := range []struct {
		name      string
		data      []byte
		wantErr   error
		wantChain int
	}{
		{name: "PKCS#8 key and certificate", data: append(append([]byte{}, cert...), pemBlock(pemPrivateKey, pkcs8)...)},
		{name: "PKCS#1 key before certificate", data: append(pemBlock(pemRSAPrivateKey, x509.MarshalPKCS1PrivateKey(key)), cert...)},
		{name: "certificate chain", data: append(append(append([]byte{}, cert...), pemBlock(pemCertificate, other.Certificate().Raw)...), pemBlock(pemPrivateKey, pkcs8)...), wantChain: 1},
		{name: "key of another certificate", data: append(pemBlock(pemCertificate, other.Certificate().Raw), pemBlock(pemPrivateKey, pkcs8)...), wantErr: ErrKeyMismatch},
		{name: "missing key", data: cert, wantErr: errors.New("eet: certificate and key are required")},
		{name: "empty input", data: nil, wantErr: errors.New("eet: certificate and key are required")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePEM(tc.data)
			if tc.wantErr != nil {
				if err == nil || (!errors.Is(err, tc.wantErr) && err.Error() != tc.wantErr.Error()) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.EIC() != testEIC || len(got.Chain()) != tc.wantChain {
				t.Fatalf("signer %s with %d chain certificates", got.EIC(), len(got.Chain()))
			}
		})
	}
}

func TestSignerEncodePKCS12(t *testing.T) {
	t.Parallel()
	s := playgroundSigner(t, testEIC)
	opaque, err := NewSigner(s.Certificate(), opaqueKey{s.Key()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		signer  *Signer
		wantErr error
	}{
		{name: "exportable key", signer: s},
		{name: "key held by an external signer", signer: opaque, wantErr: ErrKeyNotExportable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p12, err := tc.signer.EncodePKCS12("n3w-Passw0rd")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			back, err := LoadPKCS12(p12, "n3w-Passw0rd")
			if err != nil {
				t.Fatal(err)
			}
			if !back.Certificate().Equal(s.Certificate()) || len(back.Chain()) != len(s.Chain()) {
				t.Fatal("re-encoded PKCS#12 does not round-trip")
			}
		})
	}
}

func TestSignerRenewalDue(t *testing.T) {
	t.Parallel()
	s := playgroundSigner(t, testEIC)
	notAfter := s.NotAfter()
	for _, tc := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{name: "well before expiry", now: notAfter.Add(-RenewalWindow - time.Second), want: false},
		{name: "window opens", now: notAfter.Add(-RenewalWindow), want: true},
		{name: "expired", now: notAfter.Add(time.Hour), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := s.RenewalDue(tc.now); got != tc.want {
				t.Fatalf("RenewalDue(%v) = %v, want %v", tc.now, got, tc.want)
			}
		})
	}
}
