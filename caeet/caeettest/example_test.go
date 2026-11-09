package caeettest_test

import (
	"context"
	"fmt"
	"log"
	"testing"

	"github.com/noona-hq/eet2-go-sdk/caeet"
	"github.com/noona-hq/eet2-go-sdk/caeet/caeettest"
	"github.com/noona-hq/eet2-go-sdk/eet"
)

func ExampleNewServer() {
	var t *testing.T
	var signer *eet.Signer

	srv := caeettest.NewServer(t)
	srv.Trust(signer.Certificate())
	srv.Enqueue(caeettest.Renewal{PollsBeforeIssued: 1})
	ca, err := caeet.New(srv.Environment(), signer)
	if err != nil {
		log.Fatal(err)
	}
	bundle, err := ca.RenewCertificate(context.Background(), func(*caeet.Bundle) error { return nil })
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(bundle.Certificate.ValidTo)
}
