package eet

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

type Signer struct {
	cert  *x509.Certificate
	key   crypto.Signer
	chain []*x509.Certificate
}

func NewSigner(cert *x509.Certificate, key crypto.Signer, chain ...*x509.Certificate) (*Signer, error) {
	if cert == nil || key == nil {
		return nil, errors.New("eet: certificate and key are required")
	}
	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSA
	}
	keyPub, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSA
	}
	if !certPub.Equal(keyPub) {
		return nil, ErrKeyMismatch
	}
	return &Signer{cert: cert, key: key, chain: chain}, nil
}

func LoadPKCS12(data []byte, password string) (*Signer, error) {
	key, cert, chain, err := pkcs12.DecodeChain(data, password)
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		return nil, ErrIncorrectPassword
	}
	if err != nil {
		return nil, fmt.Errorf("eet: decoding PKCS#12: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrNotRSA
	}
	return NewSigner(cert, signer, chain...)
}

func (s *Signer) Certificate() *x509.Certificate {
	return s.cert
}

func (s *Signer) Chain() []*x509.Certificate {
	return s.chain
}

func (s *Signer) Key() crypto.Signer {
	return s.key
}

func (s *Signer) EIC() string {
	return s.cert.Subject.CommonName
}

func (s *Signer) NotAfter() time.Time {
	return s.cert.NotAfter
}

func (s *Signer) ValidAt(t time.Time) bool {
	return !t.Before(s.cert.NotBefore) && !t.After(s.cert.NotAfter)
}
