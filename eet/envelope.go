package eet

import (
	"github.com/noona-hq/eet2-go-sdk/internal/wssec"
)

const (
	NamespaceEET   = "http://fs.gov.cz/eet/schema/v4"
	SOAPAction     = "http://fs.gov.cz/eet/OdeslaniTrzby"
	MaxMessageSize = 12 * 1024

	eetPrefix = "v4"
)

func formatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func trzba(h header, s Sale, f wssec.Form) string {
	return "<v4:Trzba>" + wssec.EmptyElement("v4:Hlavicka", h.attrs(), f) + wssec.EmptyElement("v4:Data", s.attrs(), f) + "</v4:Trzba>"
}

func buildEnvelope(signer *Signer, h header, s Sale, ids wssec.IDs) ([]byte, error) {
	return wssec.Sign(wssec.Envelope{
		Certificate: signer.cert,
		Key:         signer.key,
		IDs:         ids,
		Payload: wssec.Payload{
			Namespace: wssec.Namespace{Prefix: eetPrefix, URI: NamespaceEET},
			Document:  trzba(h, s, wssec.Document),
			Canonical: trzba(h, s, wssec.Canonical),
		},
	})
}
