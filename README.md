# eet2-go-sdk

Go client for the Czech electronic registration of sales **EET 2.0** (Act No. 180/2026 Coll., data interface v4.1), mandatory from 1 January 2027.

It builds the registered sale data message, signs it with the cash register certificate (WS-Security, exclusive C14N, RSA-SHA256), sends it to the Financial Administration and returns the acknowledgement code (POK). The `caeet` package renews cash register certificates through the CA EET API.

Implemented against the official documents from https://eet.gov.cz/cs/pro-vyvojare/dokumenty-ke-stazeni:

- Data interface description v1.2a (2 October 2026)
- `EETXMLSchema.xsd` and `EETServiceSOAP.wsdl` v4.1
- Item descriptions with examples v1.0 (5 October 2026)
- Playground and production access and operational information v1.1
- CA EET certificate procedures v2 and `caeetapi_jwt.yml`

## Installation

Requires Go 1.27 or later.

```bash
go get github.com/noona-hq/eet2-go-sdk@latest
```

| Package | Purpose |
| --- | --- |
| `github.com/noona-hq/eet2-go-sdk/eet` | Build, sign and send registered sales; parse and verify responses |
| `github.com/noona-hq/eet2-go-sdk/eet/eettest` | Local EET endpoint for testing an integration |
| `github.com/noona-hq/eet2-go-sdk/caeet` | Renew cash register certificates through the CA EET API |

## Usage

```go
import "github.com/noona-hq/eet2-go-sdk/eet"
```

```go
p12, err := os.ReadFile("cash-register.p12")
signer, err := eet.LoadPKCS12(p12, password)
client, err := eet.NewClient(eet.Production, signer)

resp, err := client.Send(ctx, eet.Sale{
	EIC:            "CZ00000019",
	UnitID:         303,
	RegisterID:     "POKLADNA 1",
	SequenceNumber: "2027/000123",
	Time:           paidAt,
	Total:          eet.Crowns(250),
})
fmt.Println(resp.POK)
```

| Environment | Endpoint | Earliest accepted sale time |
| --- | --- | --- |
| `eet.Production` | `trzbyeet.gov.cz` | 1 January 2027; 1 November 2026 before go-live |
| `eet.Playground` | `pg.trzbyeet.gov.cz` | 1 July 2026; POKs end with `-ff` and are not valid |

A custom `eet.Environment{URL: ...}` points the client at any other endpoint. `client.Lint(sale)` runs the server's non-critical checks locally against the client's certificate and environment.

| Method | Header | Use |
| --- | --- | --- |
| `Send` | `prvni_zaslani=true` | First attempt, at the latest when the sale happens |
| `Resend` | `prvni_zaslani=false` | Every later attempt until a POK arrives |
| `Verify` | `overeni=true` | Verification mode; success is error code 0, no POK |
| `Prepare` + `Message.Send` | any | Store the message UUID per attempt before sending |

Every attempt gets a new `uuid_zpravy` and `dat_odesl`, while `Data` stays unchanged. `Message.Send` refuses to send the same message twice.

## Mapping to the specification

| XML | `Sale` field | Notes |
| --- | --- | --- |
| `eic_popl` | `EIC` | `^CZ[0-9]{8,10}$` |
| `eic_poverujiciho` | `DelegatingEIC` | Omitted when empty |
| `povereni_vice_popl` | `MultipleTaxpayers` | Emitted only when true |
| `id_jednotky` | `UnitID` | 1..999999999 |
| `id_pokl` | `RegisterID` | `^[0-9a-zA-Z\.,:;/#\-_ ]{1,20}$` |
| `porad_cis` | `SequenceNumber` | Same alphabet, 1..25 characters |
| `dat_trzby` | `Time` | Formatted with its own zone offset |
| `celk_trzba` | `Total` | `Amount` in halers, canonical `-?d.dd` |
| `urceno_cerp_zuct` | `TopUp` | Top-up of a closed-loop payment instrument |
| `cerp_zuct` | `Drawdown` | Drawdown from such an instrument |

- **Storno and corrections:** a new sale with a negative amount and the current time. It is not linked to the original sale.
- **`Sale.Validate`:** enforces the XSD, which covers the critical checks the client can perform.
- **`Sale.Lint`:** reproduces the non-critical checks behind warning codes 1, 2, 4, 5, 6 and 7.
- **`Sale.Key`:** returns the uniqueness string from chapter 4 of the interface description.

## Transport

- HTTPS with TLS 1.2 or later; HTTP/1.1 only.
- `Content-Type: text/xml; charset=utf-8`, plus `SOAPAction`.
- The response time limit defaults to 3 s. `WithTimeout` refuses anything below the legal minimum of 2 s.
- Messages over 12 kB are refused before sending.
- `X-Global-Transaction-Id` is returned as `TransactionID` on responses and errors.
- The production DNS name is resolved on every new connection.

## Errors

| Error | Meaning | What to do |
| --- | --- | --- |
| `eet.ValidationErrors` (each a `*ValidationError`) | Sale violates the schema; every violation is listed | Fix the data |
| `*TransportError` | No response within the time limit, or a network failure | `Resend` as soon as possible, within 48 h of the sale |
| `*ResponseError` with `Temporary()` | Codes -1 to -999 | Resend later |
| `*ResponseError`, other codes | Rejected message | Do not resend unchanged |
| `*SOAPFault`, `*HTTPError` | Technical rejection | Resend later |
| `ErrInvalidSignature`, `ErrResponseNotSigned` | The acknowledgement could not be verified | The response is returned for inspection; do not treat its POK as confirmed |

`eet.ShouldResend(err)` answers the only question most callers have: keep the sale and `Resend` it later, or give up. It is true for every outcome without a confirmed POK and false for invalid data, rejected messages and an expired certificate. Every error carries the `MessageUUID` of the attempt.

Acknowledgements must carry a valid XML signature. Data is read only from the signed SOAP Body.

By default the signer's `O` must be `Generální finanční ředitelství`. To also verify the certificate chain up to I.CA, use `WithResponseTrust`.

## Resending and storno

When `ShouldResend` is true, store the sale and call `Resend` as soon as the cause is gone. The law requires it within 48 hours of the sale (`Sale.ResendDeadline()`), and the obligation continues after that.

`Sale` and `Amount` marshal to JSON and text, so an unconfirmed sale can be stored and loaded unchanged. Amounts are always strings such as `"123.45"`; a JSON number is rejected so that `20` is never read as 20 halers.

A storno is a new sale with negative amounts, its own sequence number and the time of the refund. It is not linked to the original sale:

```go
storno := sale.Reversal(eet.Reversal{Time: refundedAt, SequenceNumber: "2027/000124"})
```

## Many taxpayers

Every taxpayer signs with their own certificate. `WithSigner` returns a client for another certificate that shares the environment, options and HTTP connections:

```go
shared, err := eet.NewClient(eet.Production, anySigner, eet.WithLogger(logger))
company, err := shared.WithSigner(companySigner)
```

`WithLogger(*slog.Logger)` logs one record per attempt with the UUID, taxpayer, unit, register, sequence number, duration, transaction ID, POK, error and whether to resend.

## Certificates

| Function | Use |
| --- | --- |
| `eet.LoadPKCS12(data, password)` | The `.p12` file issued by CA EET, including its legacy 3DES encryption |
| `eet.ParsePEM(data)` | Certificate, chain and PKCS#1 or PKCS#8 key from one PEM blob, for example from a secret store |
| `eet.NewSigner(cert, key)` | Any `crypto.Signer`, so the key can stay in a KMS or HSM |
| `Signer.EncodePKCS12(password)` | Re-wrap an exportable key in a modern PKCS#12 for storage |
| `Signer.RenewalDue(now)` | True within `eet.RenewalWindow` (21 days) of expiry |

## Testing your integration

`eettest.NewServer(t)` (or `eettest.Start()` with `Close()` outside a test, for example in `TestMain`) starts a local EET endpoint that verifies request signatures, records every received sale and signs acknowledgements with its own certificate. `srv.NewClient(signer)` returns a client that trusts it. Script replies with `Enqueue`:

```go
srv := eettest.NewServer(t)
srv.Enqueue(eettest.TemporaryError(), eettest.Accept(), eettest.Unavailable(), eettest.Accept().After(5*time.Second))
client, err := srv.NewClient(signer)
received := srv.Requests()
```

## Certificate renewal

```go
ca, err := caeet.New(caeet.Production, signer)
bundle, err := ca.RenewCertificate(ctx, func(b *caeet.Bundle) error {
	return vault.Store(b.PKCS12, b.Password)
})
newSigner, err := bundle.Signer()
client.SetSigner(newSigner)
```

1. Authentication uses a JWT signed by the certificate being renewed: RS256 with `x5t#S256`, and `exp - iat` of at most 5 minutes.
2. The flow is `not-finished` → `renew` → poll `status` → `claim-download` → store → `ack-download`.
3. The download is acknowledged only after `store` succeeds.
4. Renew when `Signer.RenewalDue(now)` becomes true, three weeks before expiry.

`caeet.Production`, `caeet.Trial` and `caeet.Test` select the CA EET API environment.
