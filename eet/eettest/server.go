package eettest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noona-hq/eet2-go-sdk/eet"
	"github.com/noona-hq/eet2-go-sdk/internal/wssec"
)

const (
	EnvironmentName = "eettest"

	signerKeyBits    = 2048
	signerValidity   = 24 * time.Hour
	signerName       = "eettest"
	responsePrefix   = "eet"
	pokTestSuffix    = "-ff"
	maxRequestSize   = 1 << 20
	contentTypeXML   = "text/xml;charset=UTF-8"
	contentTypeHTML  = "text/html"
	transactionIDLen = 12

	pokRandomBytes  = 16
	uuidVersionByte = 6
	uuidVariantByte = 8
	uuidVersionMask = 0x0f
	uuidVersion4    = 0x40
	uuidVariantMask = 0x3f
	uuidVariantRFC  = 0x80
)

const (
	verificationOKMessage   = "Datovou zpravu evidovane trzby v overovacim modu se podarilo zpracovat"
	messageTooLargeMessage  = "Datova zprava je prilis velka"
	invalidSignatureMessage = "Neplatny podpis SOAP zpravy"
	schemaViolationMessage  = "XML zprava nevyhovela kontrole XML schematu"
)

var textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#xD;")

type Server struct {
	srv  *httptest.Server
	cert *x509.Certificate
	key  *rsa.PrivateKey

	mu       sync.Mutex
	replies  []Reply
	requests []Request
}

func NewServer(tb testing.TB) *Server {
	tb.Helper()
	s, err := Start()
	if err != nil {
		tb.Fatalf("eettest: %v", err)
	}
	tb.Cleanup(s.Close)
	return s
}

func Start() (*Server, error) {
	key, cert, err := newSigningCertificate()
	if err != nil {
		return nil, err
	}
	s := &Server{cert: cert, key: key}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s, nil
}

func (s *Server) Close() {
	s.srv.Close()
}

func (s *Server) SignerOrganization() string {
	return signerName
}

func newSigningCertificate() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, signerKeyBits)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: signerName, Organization: []string{signerName}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(signerValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func (s *Server) URL() string {
	return s.srv.URL
}

func (s *Server) Environment() eet.Environment {
	return eet.Environment{Name: EnvironmentName, URL: s.srv.URL}
}

func (s *Server) ClientOptions() []eet.Option {
	return []eet.Option{eet.WithResponseCertificateCheck(func(cert *x509.Certificate) error {
		if !cert.Equal(s.cert) {
			return errors.New("eettest: response not signed by the test server")
		}
		return nil
	})}
}

func (s *Server) NewClient(signer *eet.Signer, opts ...eet.Option) (*eet.Client, error) {
	base := append([]eet.Option{eet.WithSigner(signer)}, s.ClientOptions()...)
	return eet.NewClient(s.Environment(), append(base, opts...)...)
}

func (s *Server) Enqueue(replies ...Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies = append(s.replies, replies...)
}

func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

func (s *Server) nextReply() Reply {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.replies) == 0 {
		return Accept()
	}
	r := s.replies[0]
	s.replies = s.replies[1:]
	return r
}

func (s *Server) record(r Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxRequestSize))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, code, message := s.inspect(raw)
	reply := s.nextReply()
	accepted := code == nil && reply.kind == replyAccept && !req.Verification
	if accepted {
		req.POK = newPOK()
	}
	s.record(req)
	if reply.delay > 0 {
		select {
		case <-time.After(reply.delay):
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set(eet.TransactionIDHeader, randomHex(transactionIDLen))
	switch {
	case code != nil:
		s.writeError(w, errorReply{uuid: req.MessageUUID, code: *code, message: message})
	case reply.kind == replyUnavailable:
		w.Header().Set("Content-Type", contentTypeHTML)
		w.WriteHeader(http.StatusServiceUnavailable)
		writeBody(w, unavailableBody)
	case reply.kind == replyReject:
		s.writeError(w, errorReply{uuid: req.MessageUUID, code: reply.code, message: reply.message})
	case req.Verification:
		s.writeError(w, errorReply{uuid: req.MessageUUID, code: eet.CodeVerificationOK, message: verificationOKMessage, warnings: reply.warnings})
	default:
		s.writeAcknowledgement(w, req, reply.warnings)
	}
}

func (s *Server) inspect(raw []byte) (Request, *int, string) {
	if len(raw) > eet.MaxMessageSize {
		return Request{}, new(eet.CodeMessageTooLarge), messageTooLargeMessage
	}
	v, err := wssec.Verify(raw)
	if err != nil {
		return Request{}, new(eet.CodeInvalidSignature), invalidSignatureMessage
	}
	req, err := parseRequest(v.CanonicalBody)
	if err != nil {
		return Request{}, new(eet.CodeSchemaViolation), schemaViolationMessage
	}
	req.SignerEIC = v.Certificate.Subject.CommonName
	if err := req.Sale.Validate(); err != nil {
		return req, new(eet.CodeSchemaViolation), schemaViolationMessage
	}
	return req, nil, ""
}

type errorReply struct {
	uuid     string
	code     int
	message  string
	warnings []eet.Warning
}

func (s *Server) writeError(w http.ResponseWriter, e errorReply) {
	hlavicka := []wssec.Attr{{Name: "dat_odmit", Value: eet.FormatDateTime(time.Now().In(eet.Prague))}}
	if e.uuid != "" {
		hlavicka = append(hlavicka, wssec.Attr{Name: "uuid_zpravy", Value: e.uuid})
	}
	odpoved := "<eet:Odpoved>" +
		wssec.EmptyElement("eet:Hlavicka", hlavicka, wssec.Document) +
		fmt.Sprintf(`<eet:Chyba kod="%d" test="true">%s</eet:Chyba>`, e.code, textEscaper.Replace(e.message)) +
		warningElements(e.warnings) +
		"</eet:Odpoved>"
	envelope := `<soapenv:Envelope xmlns:soapenv="` + wssec.NamespaceSOAP + `" xmlns:eet="` + eet.NamespaceEET + `"><soapenv:Header/><soapenv:Body>` + odpoved + `</soapenv:Body></soapenv:Envelope>`
	w.Header().Set("Content-Type", contentTypeXML)
	writeBody(w, envelope)
}

func (s *Server) writeAcknowledgement(w http.ResponseWriter, req Request, warnings []eet.Warning) {
	hlavicka := []wssec.Attr{
		{Name: "uuid_zpravy", Value: req.MessageUUID},
		{Name: "dat_prij", Value: eet.FormatDateTime(time.Now().In(eet.Prague))},
	}
	potvrzeni := []wssec.Attr{{Name: "pok", Value: req.POK}, {Name: "test", Value: "true"}}
	odpoved := func(f wssec.Form) string {
		return "<eet:Odpoved>" +
			wssec.EmptyElement("eet:Hlavicka", hlavicka, f) +
			wssec.EmptyElement("eet:Potvrzeni", potvrzeni, f) +
			warningElements(warnings) +
			"</eet:Odpoved>"
	}
	ids, err := wssec.NewIDs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	signed, err := wssec.Sign(wssec.Envelope{
		Certificate: s.cert,
		Key:         s.key,
		IDs:         ids,
		Payload: wssec.Payload{
			Namespace: wssec.Namespace{Prefix: responsePrefix, URI: eet.NamespaceEET},
			Document:  odpoved(wssec.Document),
			Canonical: odpoved(wssec.Canonical),
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeXML)
	writeBody(w, string(signed))
}

func warningElements(warnings []eet.Warning) string {
	var b strings.Builder
	for _, wn := range warnings {
		fmt.Fprintf(&b, `<eet:Varovani kod_varov="%d">%s</eet:Varovani>`, wn.Code, textEscaper.Replace(wn.Message))
	}
	return b.String()
}

func writeBody(w http.ResponseWriter, body string) {
	if _, err := io.WriteString(w, body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func newPOK() string {
	b := make([]byte, pokRandomBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[uuidVersionByte] = b[uuidVersionByte]&uuidVersionMask | uuidVersion4
	b[uuidVariantByte] = b[uuidVariantByte]&uuidVariantMask | uuidVariantRFC
	return fmt.Sprintf("%x-%x-%x-%x-%x%s", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16], pokTestSuffix)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}
