package wssec

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

var (
	ErrMalformed        = errors.New("wssec: malformed SOAP message")
	ErrUnsigned         = errors.New("wssec: message is not signed")
	ErrInvalidSignature = errors.New("wssec: invalid message signature")
)

const (
	attrAlgorithm  = "Algorithm"
	attrURI        = "URI"
	attrPrefixList = "PrefixList"
	attrID         = "Id"
	sameDocPrefix  = "#"
)

type xmlName struct {
	space string
	local string
}

var (
	nameEnvelope               = xmlName{NamespaceSOAP, "Envelope"}
	nameBody                   = xmlName{NamespaceSOAP, "Body"}
	nameHeader                 = xmlName{NamespaceSOAP, "Header"}
	nameSecurity               = xmlName{NamespaceWSSE, "Security"}
	nameBinarySecurityToken    = xmlName{NamespaceWSSE, "BinarySecurityToken"}
	nameSecurityTokenReference = xmlName{NamespaceWSSE, "SecurityTokenReference"}
	nameWsseReference          = xmlName{NamespaceWSSE, "Reference"}
	nameSignature              = xmlName{NamespaceDS, "Signature"}
	nameSignedInfo             = xmlName{NamespaceDS, "SignedInfo"}
	nameCanonicalizationMethod = xmlName{NamespaceDS, "CanonicalizationMethod"}
	nameSignatureMethod        = xmlName{NamespaceDS, "SignatureMethod"}
	nameReference              = xmlName{NamespaceDS, "Reference"}
	nameTransforms             = xmlName{NamespaceDS, "Transforms"}
	nameTransform              = xmlName{NamespaceDS, "Transform"}
	nameDigestMethod           = xmlName{NamespaceDS, "DigestMethod"}
	nameDigestValue            = xmlName{NamespaceDS, "DigestValue"}
	nameSignatureValue         = xmlName{NamespaceDS, "SignatureValue"}
	nameKeyInfo                = xmlName{NamespaceDS, "KeyInfo"}
	nameX509Data               = xmlName{NamespaceDS, "X509Data"}
	nameX509Certificate        = xmlName{NamespaceDS, "X509Certificate"}
	nameInclusiveNamespaces    = xmlName{AlgExcC14N, "InclusiveNamespaces"}
)

func (n xmlName) matches(el *etree.Element) bool {
	return el.NamespaceURI() == n.space && el.Tag == n.local
}

type Verified struct {
	CanonicalBody []byte
	Certificate   *x509.Certificate
}

func Verify(raw []byte) (*Verified, error) {
	doc := etree.NewDocument()
	doc.ReadSettings.PreserveCData = true
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	env := doc.Root()
	if env == nil || !nameEnvelope.matches(env) {
		return nil, fmt.Errorf("%w: root is not a SOAP Envelope", ErrMalformed)
	}
	body, err := singleChild(env, nameBody)
	if err != nil {
		return nil, err
	}
	signature := findSignature(env)
	if signature == nil {
		return nil, ErrUnsigned
	}
	si, err := singleChild(signature, nameSignedInfo)
	if err != nil {
		return nil, invalidSig(err)
	}
	siPrefixes, err := checkSignedInfo(si)
	if err != nil {
		return nil, invalidSig(err)
	}
	ref, err := singleChild(si, nameReference)
	if err != nil {
		return nil, invalidSig(err)
	}
	canonBody, err := checkReference(ref, body)
	if err != nil {
		return nil, invalidSig(err)
	}
	canonSI, err := canonicalize(si, siPrefixes)
	if err != nil {
		return nil, invalidSig(err)
	}
	sigValueEl, err := singleChild(signature, nameSignatureValue)
	if err != nil {
		return nil, invalidSig(err)
	}
	sigValue, err := decodeBase64(sigValueEl.Text())
	if err != nil {
		return nil, invalidSig(fmt.Errorf("SignatureValue: %v", err))
	}
	cert, err := signingCertificate(env, signature)
	if err != nil {
		return nil, invalidSig(err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, invalidSig(errors.New("signing certificate does not contain an RSA key"))
	}
	siDigest := sha256.Sum256(canonSI)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, siDigest[:], sigValue); err != nil {
		return nil, invalidSig(err)
	}
	return &Verified{CanonicalBody: canonBody, Certificate: cert}, nil
}

func findSignature(env *etree.Element) *etree.Element {
	hdr := optionalChild(env, nameHeader)
	if hdr == nil {
		return nil
	}
	security := optionalChild(hdr, nameSecurity)
	if security == nil {
		return nil
	}
	return optionalChild(security, nameSignature)
}

func checkSignedInfo(si *etree.Element) (string, error) {
	canonMethod, err := singleChild(si, nameCanonicalizationMethod)
	if err != nil {
		return "", err
	}
	if alg := canonMethod.SelectAttrValue(attrAlgorithm, ""); alg != AlgExcC14N {
		return "", fmt.Errorf("unsupported canonicalization %q", alg)
	}
	sigMethod, err := singleChild(si, nameSignatureMethod)
	if err != nil {
		return "", err
	}
	if alg := sigMethod.SelectAttrValue(attrAlgorithm, ""); alg != AlgRSASHA256 {
		return "", fmt.Errorf("unsupported signature method %q", alg)
	}
	return inclusivePrefixes(canonMethod), nil
}

func checkReference(ref, body *etree.Element) ([]byte, error) {
	uri := ref.SelectAttrValue(attrURI, "")
	id, ok := strings.CutPrefix(uri, sameDocPrefix)
	if !ok || id == "" {
		return nil, fmt.Errorf("unsupported reference URI %q", uri)
	}
	if bodyID := wsuID(body); bodyID != id {
		return nil, fmt.Errorf("signature references %q, SOAP Body has wsu:Id %q", uri, bodyID)
	}
	prefixes, err := transformsPrefixList(ref)
	if err != nil {
		return nil, err
	}
	digestMethod, err := singleChild(ref, nameDigestMethod)
	if err != nil {
		return nil, err
	}
	if alg := digestMethod.SelectAttrValue(attrAlgorithm, ""); alg != AlgSHA256 {
		return nil, fmt.Errorf("unsupported digest method %q", alg)
	}
	digestEl, err := singleChild(ref, nameDigestValue)
	if err != nil {
		return nil, err
	}
	want, err := decodeBase64(digestEl.Text())
	if err != nil {
		return nil, fmt.Errorf("DigestValue: %v", err)
	}
	canon, err := canonicalize(body, prefixes)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(canon)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return nil, errors.New("body digest mismatch")
	}
	return canon, nil
}

func invalidSig(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
}

func canonicalize(el *etree.Element, prefixList string) ([]byte, error) {
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, err
	}
	return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList).Canonicalize(detached)
}

func transformsPrefixList(ref *etree.Element) (string, error) {
	transforms := optionalChild(ref, nameTransforms)
	if transforms == nil {
		return "", errors.New("reference has no exclusive canonicalization transform")
	}
	var found *etree.Element
	for _, t := range transforms.ChildElements() {
		if !nameTransform.matches(t) {
			continue
		}
		if alg := t.SelectAttrValue(attrAlgorithm, ""); alg != AlgExcC14N {
			return "", fmt.Errorf("unsupported transform %q", alg)
		}
		if found != nil {
			return "", errors.New("multiple canonicalization transforms")
		}
		found = t
	}
	if found == nil {
		return "", errors.New("reference has no exclusive canonicalization transform")
	}
	return inclusivePrefixes(found), nil
}

func inclusivePrefixes(el *etree.Element) string {
	inc := optionalChild(el, nameInclusiveNamespaces)
	if inc == nil {
		return ""
	}
	return inc.SelectAttrValue(attrPrefixList, "")
}

func signingCertificate(env, signature *etree.Element) (*x509.Certificate, error) {
	keyInfo := optionalChild(signature, nameKeyInfo)
	if keyInfo == nil {
		return nil, errors.New("signature has no KeyInfo")
	}
	if x509Data := optionalChild(keyInfo, nameX509Data); x509Data != nil {
		certEl := optionalChild(x509Data, nameX509Certificate)
		if certEl == nil {
			return nil, errors.New("X509Data has no X509Certificate")
		}
		return parseCertBase64(certEl.Text())
	}
	str := optionalChild(keyInfo, nameSecurityTokenReference)
	if str == nil {
		return nil, errors.New("KeyInfo has neither X509Data nor SecurityTokenReference")
	}
	reference := optionalChild(str, nameWsseReference)
	if reference == nil {
		return nil, errors.New("SecurityTokenReference has no Reference")
	}
	uri := reference.SelectAttrValue(attrURI, "")
	id, ok := strings.CutPrefix(uri, sameDocPrefix)
	if !ok {
		return nil, fmt.Errorf("unsupported token reference %q", uri)
	}
	token, err := findToken(env, id)
	if err != nil {
		return nil, err
	}
	return parseCertBase64(token.Text())
}

func findToken(env *etree.Element, id string) (*etree.Element, error) {
	var token *etree.Element
	for _, el := range env.FindElements("//" + nameBinarySecurityToken.local) {
		if !nameBinarySecurityToken.matches(el) || wsuID(el) != id {
			continue
		}
		if token != nil {
			return nil, fmt.Errorf("duplicate token %q", id)
		}
		token = el
	}
	if token == nil {
		return nil, fmt.Errorf("token %q not found", id)
	}
	return token, nil
}

func parseCertBase64(s string) (*x509.Certificate, error) {
	der, err := decodeBase64(s)
	if err != nil {
		return nil, fmt.Errorf("certificate: %v", err)
	}
	return x509.ParseCertificate(der)
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
}

func wsuID(el *etree.Element) string {
	for _, a := range el.Attr {
		if a.Key == attrID && a.NamespaceURI() == NamespaceWSU {
			return a.Value
		}
	}
	return ""
}

func singleChild(parent *etree.Element, name xmlName) (*etree.Element, error) {
	var found *etree.Element
	for _, c := range parent.ChildElements() {
		if !name.matches(c) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: duplicate %s in %s", ErrMalformed, name.local, parent.Tag)
		}
		found = c
	}
	if found == nil {
		return nil, fmt.Errorf("%w: missing %s in %s", ErrMalformed, name.local, parent.Tag)
	}
	return found, nil
}

func optionalChild(parent *etree.Element, name xmlName) *etree.Element {
	for _, c := range parent.ChildElements() {
		if name.matches(c) {
			return c
		}
	}
	return nil
}
