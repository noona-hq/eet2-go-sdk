package eet

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/noona-hq/eet2-go-sdk/internal/fixtures"
	"github.com/noona-hq/eet2-go-sdk/internal/wssec"
)

type officialSample struct {
	header header
	sale   Sale
	ids    wssec.IDs
}

func sampleAttr(t *testing.T, doc, element, name string) string {
	t.Helper()
	i := strings.Index(doc, element)
	if i < 0 {
		t.Fatalf("%s not found", element)
	}
	rest := doc[i:]
	j := strings.Index(rest, " "+name+`="`)
	if j < 0 {
		t.Fatalf("%s not found in %s", name, element)
	}
	rest = rest[j+len(name)+3:]
	return rest[:strings.Index(rest, `"`)]
}

func parseOfficialSample(t *testing.T, raw []byte) officialSample {
	t.Helper()
	doc := string(raw)
	data := func(name string) string { return sampleAttr(t, doc, "<v4:Data", name) }
	amount := func(name string) Amount {
		a, err := ParseAmount(data(name))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	timestamp := func(element, name string) time.Time {
		v, err := time.Parse(time.RFC3339, sampleAttr(t, doc, element, name))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	unit, err := strconv.Atoi(data("id_jednotky"))
	if err != nil {
		t.Fatal(err)
	}
	sale := Sale{
		EIC:            data("eic_popl"),
		UnitID:         unit,
		RegisterID:     data("id_pokl"),
		SequenceNumber: data("porad_cis"),
		Time:           timestamp("<v4:Data", "dat_trzby"),
		Total:          amount("celk_trzba"),
		TopUp:          new(amount("urceno_cerp_zuct")),
		Drawdown:       new(amount("cerp_zuct")),
	}
	if strings.Contains(doc, "eic_poverujiciho") {
		sale.DelegatingEIC = data("eic_poverujiciho")
	}
	if strings.Contains(doc, "povereni_vice_popl") {
		sale.MultipleTaxpayers = data("povereni_vice_popl") == "true"
	}
	return officialSample{
		header: header{
			uuid:         sampleAttr(t, doc, "<v4:Hlavicka", "uuid_zpravy"),
			sentAt:       timestamp("<v4:Hlavicka", "dat_odesl"),
			firstSending: sampleAttr(t, doc, "<v4:Hlavicka", "prvni_zaslani") == "true",
			verification: new(sampleAttr(t, doc, "<v4:Hlavicka", "overeni") == "true"),
		},
		sale: sale,
		ids: wssec.IDs{
			Token:     sampleAttr(t, doc, "<wsse:BinarySecurityToken", "wsu:Id"),
			Signature: sampleAttr(t, doc, "<ds:Signature", "Id"),
			KeyInfo:   sampleAttr(t, doc, "<ds:KeyInfo", "Id"),
			TokenRef:  sampleAttr(t, doc, "<wsse:SecurityTokenReference", "wsu:Id"),
			Body:      sampleAttr(t, doc, "<soapenv:Body", "wsu:Id"),
		},
	}
}

func TestBuildEnvelope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		eic  string
	}{
		{name: "legal entity sample", eic: "CZ00000019"},
		{name: "VCP sample with delegation", eic: "CZ683555118"},
		{name: "natural person sample with delegation", eic: "CZ8551015704"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want := bytes.TrimSpace(fixtures.SampleRequest(tc.eic))
			s := parseOfficialSample(t, want)
			got, err := buildEnvelope(playgroundSigner(t, tc.eic), s.header, s.sale, s.ids)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("envelope differs from the official sample\n got: %s\nwant: %s", got, want)
			}
		})
	}
}
