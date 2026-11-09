package eet

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"testing"
)

var verificationSequencePattern = regexp.MustCompile(`porad_cis="OVERENI/[0-9]{14}"`)

func TestCheckConnection(t *testing.T) {
	t.Parallel()
	verified := `<eet:Odpoved><eet:Hlavicka uuid_zpravy="{uuid}"/><eet:Chyba kod="0" test="true">Datovou zpravu evidovane trzby v overovacim modu se podarilo zpracovat</eet:Chyba></eet:Odpoved>`
	rejected := `<eet:Odpoved><eet:Hlavicka uuid_zpravy="{uuid}"/><eet:Chyba kod="4">Neplatny podpis SOAP zpravy</eet:Chyba></eet:Odpoved>`
	accepted := `<eet:Odpoved><eet:Hlavicka uuid_zpravy="{uuid}"/><eet:Potvrzeni pok="987a6be5-6af5-44f3-b4fc-987654321000-ff" test="true"/></eet:Odpoved>`
	register := Register{EIC: testEIC, DelegatingEIC: "CZ683555118", MultipleTaxpayers: true, UnitID: 24, RegisterID: "POKLADNA 1"}
	for _, tc := range []struct {
		name    string
		odpoved string
		check   func(t *testing.T, err error)
	}{
		{name: "connection works", odpoved: verified, check: func(t *testing.T, err error) {
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "rejected", odpoved: rejected, check: func(t *testing.T, err error) {
			if re, ok := errors.AsType[*ResponseError](err); !ok || re.Code != CodeInvalidSignature {
				t.Fatalf("err = %v", err)
			}
		}},
		{name: "registered instead of verified", odpoved: accepted, check: func(t *testing.T, err error) {
			if !errors.Is(err, ErrUnexpectedVerificationResponse) {
				t.Fatalf("err = %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeEET(t, fakeResponse{status: 200, contentType: "text/xml", body: unsignedOdpoved(tc.odpoved)})
			c := newTestClient(t, fake.srv.URL, WithoutResponseSignatureVerification())
			tc.check(t, c.CheckConnection(context.Background(), register))
			_, body := fake.lastRequest(t)
			for _, want := range [][]byte{[]byte(`overeni="true"`), []byte(`celk_trzba="0.00"`), []byte(`eic_poverujiciho="CZ683555118"`), []byte(`povereni_vice_popl="true"`), []byte(`id_pokl="POKLADNA 1"`)} {
				if !bytes.Contains(body, want) {
					t.Errorf("request lacks %s", want)
				}
			}
			if !verificationSequencePattern.Match(body) {
				t.Error("request lacks the verification sequence number")
			}
		})
	}
}
