package eettest_test

import (
	"context"
	"fmt"
	"log"
	"testing"

	"github.com/noona-hq/eet2-go-sdk/eet"
	"github.com/noona-hq/eet2-go-sdk/eet/eettest"
)

func ExampleNewServer() {
	var t *testing.T
	var signer *eet.Signer
	var sale eet.Sale

	srv := eettest.NewServer(t)
	srv.Enqueue(eettest.TemporaryError(), eettest.Accept())
	client, err := srv.NewClient(signer)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := client.Send(context.Background(), sale); eet.ShouldResend(err) {
		resp, err := client.Resend(context.Background(), sale)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(resp.POK, len(srv.Requests()))
	}
}
