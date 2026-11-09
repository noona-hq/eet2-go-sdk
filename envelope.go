package eet

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

const (
	NamespaceEET   = "http://fs.gov.cz/eet/schema/v4"
	SOAPAction     = "http://fs.gov.cz/eet/OdeslaniTrzby"
	MaxMessageSize = 12 * 1024

	nsSoap = "http://schemas.xmlsoap.org/soap/envelope/"
	nsWsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	nsWsu  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	nsDs   = "http://www.w3.org/2000/09/xmldsig#"

	algExcC14N   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"
	algRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

	encodingBase64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
	valueTypeX509  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"

	signedInfoPrefixList = "soapenv v4"
	bodyPrefixList       = "v4"
)

var attrEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	`"`, "&quot;",
	"\t", "&#x9;",
	"\n", "&#xA;",
	"\r", "&#xD;",
)

type attr struct {
	name  string
	value string
}

type form int

const (
	documentForm form = iota
	canonicalForm
)

type bodyReference struct {
	id     string
	digest string
}

func formatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func renderAttrs(attrs []attr) string {
	sorted := append([]attr(nil), attrs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	var b strings.Builder
	for _, a := range sorted {
		b.WriteString(" " + a.name + `="` + attrEscaper.Replace(a.value) + `"`)
	}
	return b.String()
}

func emptyElement(name string, attrs []attr, f form) string {
	if f == canonicalForm {
		return "<" + name + renderAttrs(attrs) + "></" + name + ">"
	}
	return "<" + name + renderAttrs(attrs) + "/>"
}

func trzba(h header, s Sale, f form) string {
	return "<v4:Trzba>" + emptyElement("v4:Hlavicka", h.attrs(), f) + emptyElement("v4:Data", s.attrs(), f) + "</v4:Trzba>"
}

func canonicalBody(bodyID string, h header, s Sale) string {
	return `<soapenv:Body xmlns:soapenv="` + nsSoap + `" xmlns:v4="` + NamespaceEET + `" xmlns:wsu="` + nsWsu + `" wsu:Id="` + bodyID + `">` + trzba(h, s, canonicalForm) + `</soapenv:Body>`
}

func inclusiveNamespaces(prefixList string, f form) string {
	if f == canonicalForm {
		return `<ec:InclusiveNamespaces xmlns:ec="` + algExcC14N + `" PrefixList="` + prefixList + `"></ec:InclusiveNamespaces>`
	}
	return `<ec:InclusiveNamespaces PrefixList="` + prefixList + `" xmlns:ec="` + algExcC14N + `"/>`
}

func signedInfo(ref bodyReference, f form) string {
	open := `<ds:SignedInfo>`
	if f == canonicalForm {
		open = `<ds:SignedInfo xmlns:ds="` + nsDs + `" xmlns:soapenv="` + nsSoap + `" xmlns:v4="` + NamespaceEET + `">`
	}
	return open +
		`<ds:CanonicalizationMethod Algorithm="` + algExcC14N + `">` + inclusiveNamespaces(signedInfoPrefixList, f) + `</ds:CanonicalizationMethod>` +
		emptyElement("ds:SignatureMethod", []attr{{name: "Algorithm", value: algRSASHA256}}, f) +
		`<ds:Reference URI="#` + ref.id + `"><ds:Transforms><ds:Transform Algorithm="` + algExcC14N + `">` + inclusiveNamespaces(bodyPrefixList, f) + `</ds:Transform></ds:Transforms>` +
		emptyElement("ds:DigestMethod", []attr{{name: "Algorithm", value: algSHA256}}, f) +
		`<ds:DigestValue>` + ref.digest + `</ds:DigestValue></ds:Reference></ds:SignedInfo>`
}

func buildEnvelope(signer *Signer, h header, s Sale, ids securityIDs) ([]byte, error) {
	digest := sha256.Sum256([]byte(canonicalBody(ids.body, h, s)))
	ref := bodyReference{id: ids.body, digest: base64.StdEncoding.EncodeToString(digest[:])}

	siDigest := sha256.Sum256([]byte(signedInfo(ref, canonicalForm)))
	sig, err := signer.key.Sign(rand.Reader, siDigest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("eet: signing message: %w", err)
	}

	envelope := `<soapenv:Envelope xmlns:soapenv="` + nsSoap + `" xmlns:v4="` + NamespaceEET + `">` +
		`<soapenv:Header><wsse:Security xmlns:wsse="` + nsWsse + `" xmlns:wsu="` + nsWsu + `">` +
		`<wsse:BinarySecurityToken EncodingType="` + encodingBase64 + `" ValueType="` + valueTypeX509 + `" wsu:Id="` + ids.token + `">` +
		base64.StdEncoding.EncodeToString(signer.cert.Raw) +
		`</wsse:BinarySecurityToken>` +
		`<ds:Signature Id="` + ids.signature + `" xmlns:ds="` + nsDs + `">` +
		signedInfo(ref, documentForm) +
		`<ds:SignatureValue>` + base64.StdEncoding.EncodeToString(sig) + `</ds:SignatureValue>` +
		`<ds:KeyInfo Id="` + ids.keyInfo + `"><wsse:SecurityTokenReference wsu:Id="` + ids.tokenRef + `">` +
		`<wsse:Reference URI="#` + ids.token + `" ValueType="` + valueTypeX509 + `"/>` +
		`</wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature></wsse:Security></soapenv:Header>` +
		`<soapenv:Body wsu:Id="` + ids.body + `" xmlns:wsu="` + nsWsu + `">` +
		trzba(h, s, documentForm) +
		`</soapenv:Body></soapenv:Envelope>`
	return []byte(envelope), nil
}
