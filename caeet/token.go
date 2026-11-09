package caeet

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	MaxTokenLifetime     = 5 * time.Minute
	DefaultTokenLifetime = 2 * time.Minute

	tokenAlgorithm = "RS256"
	tokenType      = "JWT"
)

type tokenHeader struct {
	Alg       string `json:"alg"`
	Typ       string `json:"typ"`
	X5tSHA256 string `json:"x5t#S256"`
}

type tokenClaims struct {
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

func (c *Client) Token() (string, error) {
	thumb := sha256.Sum256(c.cert.Raw)
	header, err := json.Marshal(tokenHeader{
		Alg:       tokenAlgorithm,
		Typ:       tokenType,
		X5tSHA256: base64.RawURLEncoding.EncodeToString(thumb[:]),
	})
	if err != nil {
		return "", err
	}
	iat := time.Now().Unix()
	claims, err := json.Marshal(tokenClaims{IssuedAt: iat, ExpiresAt: iat + int64(c.lifetime/time.Second)})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := c.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("caeet: signing token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
