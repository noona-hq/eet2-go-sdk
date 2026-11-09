package eet

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"slices"
	"time"
)

const ResponseSignerOrganization = "Generální finanční ředitelství"

type Option func(*Client) error

type ResponseTrust struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
}

func WithTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d < MinTimeout {
			return ErrTimeoutTooShort
		}
		c.timeout = d
		return nil
	}
}

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) error {
		c.http = h
		return nil
	}
}

func WithoutResponseSignatureVerification() Option {
	return func(c *Client) error {
		c.verify = false
		return nil
	}
}

func WithResponseCertificateCheck(check func(*x509.Certificate) error) Option {
	return func(c *Client) error {
		c.certCheck = check
		return nil
	}
}

func WithResponseTrust(trust ResponseTrust) Option {
	return WithResponseCertificateCheck(func(cert *x509.Certificate) error {
		if err := CheckResponseSignerOrganization(cert); err != nil {
			return err
		}
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:         trust.Roots,
			Intermediates: trust.Intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		return err
	})
}

func CheckResponseSignerOrganization(cert *x509.Certificate) error {
	if slices.Contains(cert.Subject.Organization, ResponseSignerOrganization) {
		return nil
	}
	return fmt.Errorf("eet: response signer organization %q is not %q", cert.Subject.Organization, ResponseSignerOrganization)
}
