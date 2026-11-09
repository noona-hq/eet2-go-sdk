package wssec

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/noona-hq/eet2-go-sdk/internal/fixtures"
	"software.sslmate.com/src/go-pkcs12"
)

func playgroundKey(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, cert, _, err := pkcs12.DecodeChain(fixtures.PlaygroundP12(fixtures.EICLegalEntity), fixtures.PlaygroundPassword())
	if err != nil {
		t.Fatal(err)
	}
	return key.(crypto.Signer), cert
}

func TestSign(t *testing.T) {
	t.Parallel()
	key, cert := playgroundKey(t)
	ids, err := NewIDs()
	if err != nil {
		t.Fatal(err)
	}
	attrs := []Attr{{Name: "b", Value: `x"&<y`}, {Name: "a", Value: "1"}}
	for _, tc := range []struct {
		name    string
		payload Payload
	}{
		{name: "empty element payload", payload: Payload{
			Namespace: Namespace{Prefix: "p", URI: "urn:test"},
			Document:  EmptyElement("p:Item", attrs, Document),
			Canonical: EmptyElement("p:Item", attrs, Canonical),
		}},
		{name: "nested payload", payload: Payload{
			Namespace: Namespace{Prefix: "v4", URI: "urn:other"},
			Document:  "<v4:Outer>" + EmptyElement("v4:Inner", attrs, Document) + "</v4:Outer>",
			Canonical: "<v4:Outer>" + EmptyElement("v4:Inner", attrs, Canonical) + "</v4:Outer>",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := Sign(Envelope{Certificate: cert, Key: key, IDs: ids, Payload: tc.payload})
			if err != nil {
				t.Fatal(err)
			}
			v, err := Verify(raw)
			if err != nil {
				t.Fatalf("signed envelope does not verify: %v", err)
			}
			if v.Certificate.Subject.CommonName != fixtures.EICLegalEntity {
				t.Fatalf("signed by %q", v.Certificate.Subject.CommonName)
			}
		})
	}
}

func TestEmptyElement(t *testing.T) {
	t.Parallel()
	attrs := []Attr{{Name: "z", Value: "\t\n\r"}, {Name: "a", Value: `"&<`}}
	for _, tc := range []struct {
		name string
		form Form
		want string
	}{
		{name: "document", form: Document, want: `<x a="&quot;&amp;&lt;" z="&#x9;&#xA;&#xD;"/>`},
		{name: "canonical", form: Canonical, want: `<x a="&quot;&amp;&lt;" z="&#x9;&#xA;&#xD;"></x>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := EmptyElement("x", attrs, tc.form); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}
