package eet_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/noona-hq/eet2-go-sdk/eet"
)

func ExampleNewClient() {
	p12, err := os.ReadFile("cash-register.p12")
	if err != nil {
		log.Fatal(err)
	}
	signer, err := eet.LoadPKCS12(p12, os.Getenv("EET_P12_PASSWORD"))
	if err != nil {
		log.Fatal(err)
	}
	client, err := eet.NewClient(eet.Production, signer, eet.WithTimeout(5*time.Second))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(client.Environment().Name, client.Signer().EIC())
}

func ExampleClient_Send() {
	var client *eet.Client
	sale := eet.Sale{
		EIC:            "CZ00000019",
		UnitID:         303,
		RegisterID:     "POKLADNA 1",
		SequenceNumber: "2027/000123",
		Time:           time.Now(),
		Total:          eet.Crowns(250),
	}

	resp, err := client.Send(context.Background(), sale)
	if te, ok := errors.AsType[*eet.TransportError](err); ok {
		log.Printf("no response within the time limit, resend later with Resend: %v", te)
		return
	}
	if re, ok := errors.AsType[*eet.ResponseError](err); ok && re.Temporary() {
		log.Printf("temporary error %d, resend later with Resend", re.Code)
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("POK", resp.POK)
	for _, w := range resp.Warnings {
		log.Printf("warning %d: %s", w.Code, w.Message)
	}
}

func ExampleClient_Resend() {
	var client *eet.Client
	var unconfirmed eet.Sale

	resp, err := client.Resend(context.Background(), unconfirmed)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("POK", resp.POK)
}

func ExampleClient_Prepare() {
	var client *eet.Client
	var sale eet.Sale

	msg, err := client.Prepare(sale, eet.SendOptions{})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("attempt %s at %s", msg.UUID, msg.SentAt)
	resp, err := msg.Send(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("POK", resp.POK, "transaction", resp.TransactionID)
}

func ExampleClient_Verify() {
	var client *eet.Client
	var sale eet.Sale

	resp, err := client.Verify(context.Background(), sale)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("connection works:", resp.VerificationSucceeded())
}

func ExampleSale_topUpAndDrawdown() {
	topUp := eet.Sale{
		EIC:            "CZ00000019",
		UnitID:         1551,
		RegisterID:     "0001",
		SequenceNumber: "3210",
		Time:           time.Now(),
		Total:          eet.Crowns(1000),
		TopUp:          new(eet.Crowns(1000)),
	}
	drawdown := eet.Sale{
		EIC:            "CZ00000019",
		UnitID:         1551,
		RegisterID:     "0001",
		SequenceNumber: "3211",
		Time:           time.Now(),
		Total:          eet.Crowns(290),
		Drawdown:       new(eet.Crowns(290)),
	}
	fmt.Println(topUp.Validate(), drawdown.Validate())
}

func ExampleSale_Validate() {
	sale := eet.Sale{EIC: "CZ00000019", RegisterID: "Pokladna č. 1"}
	if ves, ok := errors.AsType[eet.ValidationErrors](sale.Validate()); ok {
		for _, ve := range ves {
			fmt.Println(ve.Field)
		}
	}
}

func ExampleParseAmount() {
	a, err := eet.ParseAmount("-187.20")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(a.Halers(), a)
}
