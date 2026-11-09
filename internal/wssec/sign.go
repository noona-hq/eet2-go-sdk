package wssec

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	NamespaceSOAP = "http://schemas.xmlsoap.org/soap/envelope/"
	NamespaceWSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	NamespaceWSU  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	NamespaceDS   = "http://www.w3.org/2000/09/xmldsig#"

	AlgExcC14N   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	AlgSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

	encodingBase64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
	valueTypeX509  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"

	soapPrefix        = "soapenv"
	wsuPrefix         = "wsu"
	dsPrefix          = "ds"
	securityIDEntropy = 16
)

type Namespace struct {
	Prefix string
	URI    string
}

type IDs struct {
	Token     string
	Signature string
	KeyInfo   string
	TokenRef  string
	Body      string
}

func NewIDs() (IDs, error) {
	b := make([]byte, securityIDEntropy)
	if _, err := rand.Read(b); err != nil {
		return IDs{}, err
	}
	base := strings.ToUpper(hex.EncodeToString(b))
	return IDs{
		Token:     "X509-" + base + "1",
		Signature: "SIG-" + base + "2",
		KeyInfo:   "KI-" + base + "3",
		TokenRef:  "STR-" + base + "4",
		Body:      "id-" + base + "5",
	}, nil
}

type Payload struct {
	Namespace Namespace
	Document  string
	Canonical string
}

type Envelope struct {
	Certificate *x509.Certificate
	Key         crypto.Signer
	IDs         IDs
	Payload     Payload
}

type bodyReference struct {
	id     string
	digest string
}

func Sign(e Envelope) ([]byte, error) {
	ns := e.Payload.Namespace
	bodyNS := namespaceDecls([]Namespace{{Prefix: soapPrefix, URI: NamespaceSOAP}, ns, {Prefix: wsuPrefix, URI: NamespaceWSU}})
	body := `<soapenv:Body` + bodyNS + ` wsu:Id="` + e.IDs.Body + `">` + e.Payload.Canonical + `</soapenv:Body>`
	digest := sha256.Sum256([]byte(body))
	ref := bodyReference{id: e.IDs.Body, digest: base64.StdEncoding.EncodeToString(digest[:])}

	siDigest := sha256.Sum256([]byte(signedInfo(ns, ref, Canonical)))
	sig, err := e.Key.Sign(rand.Reader, siDigest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("wssec: signing message: %w", err)
	}

	envelope := `<soapenv:Envelope xmlns:soapenv="` + NamespaceSOAP + `" xmlns:` + ns.Prefix + `="` + ns.URI + `">` +
		`<soapenv:Header><wsse:Security xmlns:wsse="` + NamespaceWSSE + `" xmlns:wsu="` + NamespaceWSU + `">` +
		`<wsse:BinarySecurityToken EncodingType="` + encodingBase64 + `" ValueType="` + valueTypeX509 + `" wsu:Id="` + e.IDs.Token + `">` +
		base64.StdEncoding.EncodeToString(e.Certificate.Raw) +
		`</wsse:BinarySecurityToken>` +
		`<ds:Signature Id="` + e.IDs.Signature + `" xmlns:ds="` + NamespaceDS + `">` +
		signedInfo(ns, ref, Document) +
		`<ds:SignatureValue>` + base64.StdEncoding.EncodeToString(sig) + `</ds:SignatureValue>` +
		`<ds:KeyInfo Id="` + e.IDs.KeyInfo + `"><wsse:SecurityTokenReference wsu:Id="` + e.IDs.TokenRef + `">` +
		`<wsse:Reference URI="#` + e.IDs.Token + `" ValueType="` + valueTypeX509 + `"/>` +
		`</wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature></wsse:Security></soapenv:Header>` +
		`<soapenv:Body wsu:Id="` + e.IDs.Body + `" xmlns:wsu="` + NamespaceWSU + `">` +
		e.Payload.Document +
		`</soapenv:Body></soapenv:Envelope>`
	return []byte(envelope), nil
}

func namespaceDecls(namespaces []Namespace) string {
	sorted := append([]Namespace(nil), namespaces...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Prefix < sorted[j].Prefix })
	var b strings.Builder
	for _, n := range sorted {
		b.WriteString(` xmlns:` + n.Prefix + `="` + n.URI + `"`)
	}
	return b.String()
}

func inclusiveNamespaces(prefixList string, f Form) string {
	if f == Canonical {
		return `<ec:InclusiveNamespaces xmlns:ec="` + AlgExcC14N + `" PrefixList="` + prefixList + `"></ec:InclusiveNamespaces>`
	}
	return `<ec:InclusiveNamespaces PrefixList="` + prefixList + `" xmlns:ec="` + AlgExcC14N + `"/>`
}

func signedInfo(ns Namespace, ref bodyReference, f Form) string {
	open := `<ds:SignedInfo>`
	if f == Canonical {
		open = `<ds:SignedInfo` + namespaceDecls([]Namespace{{Prefix: dsPrefix, URI: NamespaceDS}, {Prefix: soapPrefix, URI: NamespaceSOAP}, ns}) + `>`
	}
	return open +
		`<ds:CanonicalizationMethod Algorithm="` + AlgExcC14N + `">` + inclusiveNamespaces(soapPrefix+" "+ns.Prefix, f) + `</ds:CanonicalizationMethod>` +
		EmptyElement("ds:SignatureMethod", []Attr{{Name: "Algorithm", Value: AlgRSASHA256}}, f) +
		`<ds:Reference URI="#` + ref.id + `"><ds:Transforms><ds:Transform Algorithm="` + AlgExcC14N + `">` + inclusiveNamespaces(ns.Prefix, f) + `</ds:Transform></ds:Transforms>` +
		EmptyElement("ds:DigestMethod", []Attr{{Name: "Algorithm", Value: AlgSHA256}}, f) +
		`<ds:DigestValue>` + ref.digest + `</ds:DigestValue></ds:Reference></ds:SignedInfo>`
}
