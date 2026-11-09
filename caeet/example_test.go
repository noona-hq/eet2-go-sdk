package caeet_test

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/noona-hq/eet2-go-sdk/caeet"
	"github.com/noona-hq/eet2-go-sdk/eet"
)

func ExampleClient_RenewCertificate() {
	var client *eet.Client
	ca, err := caeet.New(caeet.Production, client.Signer())
	if err != nil {
		log.Fatal(err)
	}
	bundle, err := ca.RenewCertificate(context.Background(), func(b *caeet.Bundle) error {
		return os.WriteFile("cash-register.p12", b.PKCS12, 0o600)
	})
	if err != nil {
		log.Fatal(err)
	}
	renewed, err := bundle.Signer()
	if err != nil {
		log.Fatal(err)
	}
	client.SetSigner(renewed)
	fmt.Println("valid until", bundle.Certificate.ValidTo)
}
