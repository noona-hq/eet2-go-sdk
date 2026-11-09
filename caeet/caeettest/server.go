package caeettest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noona-hq/eet2-go-sdk/caeet"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	EnvironmentName = "caeettest"

	apiPrefix             = "/api"
	keyBits               = 2048
	caValidity            = 10 * 365 * 24 * time.Hour
	certificateValidity   = 366 * 24 * time.Hour
	passwordLength        = 8
	passwordAlphabet      = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	certificateTimeLayout = "2006-01-02 15:04:05Z07:00"
	retryAfterHeader      = "Retry-After"
	bearerPrefix          = "Bearer "
	thumbprintHeader      = "x5t#S256"
	tokenAlgorithm        = "RS256"
	tokenSegments         = 3
	caName                = "caeettest CA"

	msgUnauthorized       = "Unauthorized access."
	msgInvalidCertificate = "Invalid certificate."
	msgUnknownObject      = "Unknown object."
	msgConflict           = "Conflict."

	codeUnauthorized = 2
	codeNotFound     = 4
	codeConflict     = 5
)

type Renewal struct {
	PollsBeforeIssued int
	PollAfter         time.Duration
	RejectReason      string
}

type Request struct {
	Method string
	Path   string
	EIC    string
}

type request struct {
	id       string
	eic      string
	state    caeet.State
	polls    int
	renewal  Renewal
	p12      []byte
	password string
	cert     *x509.Certificate
}

type Server struct {
	srv    *httptest.Server
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey

	mu       sync.Mutex
	trusted  map[string]*x509.Certificate
	renewals []Renewal
	reqs     map[string]*request
	log      []Request
}

func NewServer(tb testing.TB) *Server {
	tb.Helper()
	s, err := Start()
	if err != nil {
		tb.Fatalf("caeettest: %v", err)
	}
	tb.Cleanup(s.Close)
	return s
}

func Start() (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: caName, Organization: []string{caName}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	s := &Server{
		caCert:  caCert,
		caKey:   key,
		trusted: map[string]*x509.Certificate{},
		reqs:    map[string]*request{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s, nil
}

func (s *Server) Close() {
	s.srv.Close()
}

func (s *Server) URL() string {
	return s.srv.URL + apiPrefix
}

func (s *Server) Environment() caeet.Environment {
	return caeet.Environment{Name: EnvironmentName, BaseURL: s.URL()}
}

func (s *Server) Root() *x509.Certificate {
	return s.caCert
}

func (s *Server) Trust(cert *x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trusted[thumbprint(cert)] = cert
}

func (s *Server) Enqueue(renewals ...Renewal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewals = append(s.renewals, renewals...)
}

func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.log...)
}

func thumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type apiError struct {
	status  int
	code    int
	message string
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, e apiError) {
	writeJSON(w, e.status, map[string]any{"code": e.code, "message": e.message})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	cert, authErr := s.authenticate(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := Request{Method: r.Method, Path: strings.TrimPrefix(r.URL.Path, apiPrefix)}
	if cert != nil {
		entry.EIC = cert.Subject.CommonName
	}
	s.log = append(s.log, entry)
	if authErr != "" {
		writeError(w, apiError{status: http.StatusUnauthorized, code: codeUnauthorized, message: authErr})
		return
	}
	eic := cert.Subject.CommonName
	parts := strings.Split(strings.Trim(entry.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && entry.Path == "/request/not-finished":
		s.notFinished(w, eic)
	case r.Method == http.MethodPost && entry.Path == "/request/renew":
		s.renew(w, eic)
	case len(parts) == 3 && parts[0] == "request":
		s.requestAction(w, requestCall{method: r.Method, id: parts[1], action: parts[2], eic: eic})
	default:
		writeError(w, apiError{status: http.StatusNotFound, code: codeNotFound, message: msgUnknownObject})
	}
}

func (s *Server) authenticate(r *http.Request) (*x509.Certificate, string) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), bearerPrefix)
	if !ok {
		return nil, msgUnauthorized
	}
	parts := strings.Split(token, ".")
	if len(parts) != tokenSegments {
		return nil, msgUnauthorized
	}
	var header map[string]string
	if err := decodeSegment(parts[0], &header); err != nil || header["alg"] != tokenAlgorithm {
		return nil, msgUnauthorized
	}
	s.mu.Lock()
	cert := s.trusted[header[thumbprintHeader]]
	s.mu.Unlock()
	if cert == nil {
		return nil, msgInvalidCertificate
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, msgUnauthorized
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) != nil {
		return nil, msgUnauthorized
	}
	var claims struct {
		IssuedAt  int64 `json:"iat"`
		ExpiresAt int64 `json:"exp"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, msgUnauthorized
	}
	now := time.Now().Unix()
	lifetime := claims.ExpiresAt - claims.IssuedAt
	if claims.ExpiresAt < now || lifetime <= 0 || lifetime > int64(caeet.MaxTokenLifetime/time.Second) {
		return nil, msgUnauthorized
	}
	if !cert.NotAfter.After(time.Now()) {
		return nil, msgInvalidCertificate
	}
	return cert, ""
}

func decodeSegment(segment string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (s *Server) notFinished(w http.ResponseWriter, eic string) {
	ids := []string{}
	for id, req := range s.reqs {
		if req.eic == eic && (req.state == caeet.StateInProcess || req.state == caeet.StateIssued || req.state == caeet.StateDelivering) {
			ids = append(ids, id)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(ids), "data": ids})
}

func (s *Server) renew(w http.ResponseWriter, eic string) {
	renewal := Renewal{}
	if len(s.renewals) > 0 {
		renewal = s.renewals[0]
		s.renewals = s.renewals[1:]
	}
	if renewal.PollAfter < time.Second {
		renewal.PollAfter = time.Second
	}
	id, err := newRequestID()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.reqs[id] = &request{id: id, eic: eic, state: caeet.StateInProcess, renewal: renewal}
	writeJSON(w, http.StatusCreated, map[string]string{"reqId": id})
}

type requestCall struct {
	method string
	id     string
	action string
	eic    string
}

func (s *Server) requestAction(w http.ResponseWriter, c requestCall) {
	req, ok := s.reqs[c.id]
	if !ok || req.eic != c.eic {
		writeError(w, apiError{status: http.StatusNotFound, code: codeNotFound, message: msgUnknownObject})
		return
	}
	switch {
	case c.method == http.MethodGet && c.action == "status":
		s.status(w, req)
	case c.method == http.MethodPost && c.action == "claim-download":
		s.claim(w, req)
	case c.method == http.MethodPost && c.action == "ack-download":
		s.ack(w, req)
	default:
		writeError(w, apiError{status: http.StatusNotFound, code: codeNotFound, message: msgUnknownObject})
	}
}

func (s *Server) status(w http.ResponseWriter, req *request) {
	if req.state == caeet.StateInProcess {
		if req.polls < req.renewal.PollsBeforeIssued {
			req.polls++
			seconds := int(req.renewal.PollAfter / time.Second)
			w.Header().Set(retryAfterHeader, strconv.Itoa(seconds))
			writeJSON(w, http.StatusOK, map[string]any{"reqId": req.id, "state": req.state, "pollAfterSeconds": seconds})
			return
		}
		if req.renewal.RejectReason != "" {
			req.state = caeet.StateRejected
		} else if err := s.issue(req); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	body := map[string]any{"reqId": req.id, "state": req.state}
	if req.state == caeet.StateRejected {
		body["rejectedReason"] = req.renewal.RejectReason
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) issue(req *request) error {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.eic, Country: []string{"CZ"}},
		NotBefore:    now,
		NotAfter:     now.Add(certificateValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, &key.PublicKey, s.caKey)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	password, err := newPassword()
	if err != nil {
		return err
	}
	p12, err := pkcs12.Legacy.Encode(key, cert, []*x509.Certificate{s.caCert}, password)
	if err != nil {
		return err
	}
	req.cert, req.p12, req.password = cert, p12, password
	req.state = caeet.StateIssued
	s.trusted[thumbprint(cert)] = cert
	return nil
}

func (s *Server) claim(w http.ResponseWriter, req *request) {
	if req.state != caeet.StateIssued && req.state != caeet.StateDelivering {
		writeError(w, apiError{status: http.StatusConflict, code: codeConflict, message: msgConflict})
		return
	}
	req.state = caeet.StateDelivering
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"pkcs12":   req.p12,
		"password": req.password,
		"certificate": map[string]any{
			"sn":        req.cert.SerialNumber.String(),
			"validFrom": req.cert.NotBefore.UTC().Format(certificateTimeLayout),
			"validTo":   req.cert.NotAfter.UTC().Format(certificateTimeLayout),
			"state":     caeet.CertificateValid,
		},
	})
}

func (s *Server) ack(w http.ResponseWriter, req *request) {
	if req.state != caeet.StateDelivering {
		writeError(w, apiError{status: http.StatusConflict, code: codeConflict, message: msgConflict})
		return
	}
	req.state = caeet.StateFinished
	req.p12, req.password = nil, ""
	w.WriteHeader(http.StatusNoContent)
}

func newRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func newPassword() (string, error) {
	out := make([]byte, passwordLength)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return string(out), nil
}
