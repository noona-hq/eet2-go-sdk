package eet

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testEIC          = "CZ00000019"
	testKeyBits      = 2048
	fakeTransaction  = "tx-123"
	responseEnvelope = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eet="http://fs.gov.cz/eet/schema/v4"><soapenv:Body>{odpoved}</soapenv:Body></soapenv:Envelope>`
)

var requestUUIDPattern = regexp.MustCompile(`uuid_zpravy="([^"]+)"`)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func playgroundSigner(t *testing.T, eic string) *Signer {
	t.Helper()
	password := strings.TrimSpace(string(readTestdata(t, "playground-p12-password.txt")))
	s, err := LoadPKCS12(readTestdata(t, "CA_EET-Playground-"+eic+".p12"), password)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func expiredSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, testKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testEIC},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(-1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testSale() Sale {
	return Sale{
		EIC:            testEIC,
		UnitID:         303,
		RegisterID:     "SDK-TEST",
		SequenceNumber: "2026/000123",
		Time:           time.Now().In(Prague).Truncate(time.Second),
		Total:          Halers(12345),
	}
}

func requestUUID(body []byte) string {
	m := requestUUIDPattern.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return string(m[1])
}

type fakeResponse struct {
	status      int
	contentType string
	body        func(requestUUID string) []byte
	delay       time.Duration
}

func staticBody(b []byte) func(string) []byte {
	return func(string) []byte { return b }
}

func unsignedOdpoved(odpoved string) func(string) []byte {
	return func(uuid string) []byte {
		return []byte(strings.ReplaceAll(strings.Replace(responseEnvelope, "{odpoved}", odpoved, 1), "{uuid}", uuid))
	}
}

type fakeEET struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func newFakeEET(t *testing.T, r fakeResponse) *fakeEET {
	t.Helper()
	f := &fakeEET{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
			return
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, req)
		f.body = append(f.body, body)
		f.mu.Unlock()
		if r.delay > 0 {
			select {
			case <-time.After(r.delay):
			case <-req.Context().Done():
				return
			}
		}
		w.Header().Set(TransactionIDHeader, fakeTransaction)
		w.Header().Set("Content-Type", r.contentType)
		w.WriteHeader(r.status)
		if _, err := w.Write(r.body(requestUUID(body))); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEET) lastRequest(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		t.Fatal("no request received")
	}
	return f.reqs[len(f.reqs)-1], f.body[len(f.body)-1]
}

func newTestClient(t *testing.T, url string, opts ...Option) *Client {
	t.Helper()
	c, err := NewClient(url, playgroundSigner(t, testEIC), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
