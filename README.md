# eet2-go-sdk

Go client for the Czech electronic registration of sales **EET 2.0** (Act No. 180/2026 Coll., data interface v4.1), mandatory from 1 January 2027.

It builds the registered sale data message, signs it with the cash register certificate (WS-Security, exclusive C14N, RSA-SHA256), sends it to the Financial Administration and returns the acknowledgement code (POK). The `caeet` package renews cash register certificates through the CA EET API.

Implemented against the official documents from https://eet.gov.cz/cs/pro-vyvojare/dokumenty-ke-stazeni:

- Data interface description v1.2a (2 October 2026)
- `EETXMLSchema.xsd` and `EETServiceSOAP.wsdl` v4.1
- Item descriptions with examples v1.0 (5 October 2026)
- Playground and production access and operational information v1.1
- CA EET certificate procedures v2 and `caeetapi_jwt.yml`

## Usage

```go
p12, err := os.ReadFile("CA_EET-Playground-CZ00000019.p12")
signer, err := eet.LoadPKCS12(p12, password)
client, err := eet.NewClient(eet.PlaygroundURL, signer)

resp, err := client.Send(ctx, eet.Sale{
	EIC:            "CZ00000019",
	UnitID:         303,
	RegisterID:     "POKLADNA 1",
	SequenceNumber: "2027/000123",
	Time:           paidAt,
	Total:          eet.Halers(25000),
})
```

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
| `urceno_cerp_zuct` | `IntendedForDrawdown` | Top-up of a closed-loop payment instrument |
| `cerp_zuct` | `DrawdownOrSettlement` | Drawdown from such an instrument |

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
| `*ValidationError` | Sale violates the schema | Fix the data |
| `*TransportError` | No response within the time limit, or a network failure | `Resend` as soon as possible, within 48 h of the sale |
| `*ResponseError` with `Temporary()` | Codes -1 to -999 | Resend later |
| `*ResponseError`, other codes | Rejected message | Do not resend unchanged |
| `*SOAPFault`, `*HTTPError` | Technical rejection | Resend later |
| `ErrInvalidSignature`, `ErrResponseNotSigned` | The acknowledgement could not be verified | The response is returned for inspection; do not treat its POK as confirmed |

Acknowledgements must carry a valid XML signature. Data is read only from the signed SOAP Body.

By default the signer's `O` must be `Generální finanční ředitelství`. To also verify the certificate chain up to I.CA, use `WithResponseTrust`.

## Certificate renewal

```go
ca, err := caeet.New(caeet.ProductionURL, signer)
bundle, err := ca.RenewCertificate(ctx, func(b *caeet.Bundle) error {
	return vault.Store(b.PKCS12, b.Password)
})
newSigner, err := bundle.Signer()
client.SetSigner(newSigner)
```

1. Authentication uses a JWT signed by the certificate being renewed: RS256 with `x5t#S256`, and `exp - iat` of at most 5 minutes.
2. The flow is `not-finished` → `renew` → poll `status` → `claim-download` → store → `ack-download`.
3. The download is acknowledged only after `store` succeeds.
4. Renew 2–3 weeks before `Signer.NotAfter()`.

## Releases

Go modules are served from git tags. Every push to `main` that passes CI and changes Go code is tagged with the next patch version (`v0.1.0` first). A GitHub Release with generated notes is created for the tag, and the version is fetched through `proxy.golang.org` so it appears on pkg.go.dev. Run the CI workflow manually to release a minor or major version.

```bash
go get github.com/noona-hq/eet2-go-sdk@latest
```

## Layout

Requires Go 1.27.

| Files | Contents |
| --- | --- |
| `sale.go`, `amount.go`, `datetime.go` | Data model and XSD validation |
| `lint.go` | Local non-critical checks (warning codes) |
| `header.go`, `envelope.go`, `signer.go` | Message header, signed SOAP envelope, cash register certificate |
| `client.go`, `options.go`, `message.go` | Client, options, sending one attempt |
| `response.go`, `verify.go`, `errors.go` | Response parsing, response signature verification, error types |
| `caeet/` | CA EET API: `client.go`, `token.go`, `requests.go`, `renew.go`, `errors.go` |

## Tests

Test conventions:

- one table-driven `TestXxx` per operation, with `t.Run` subtests;
- `t.Parallel()` everywhere;
- no test-only code paths in the library.

```bash
make lint
```

```bash
make test
```

```bash
make test-playground
```

- **Byte-for-byte check:** `TestBuildEnvelope` rebuilds the three official sample requests from the specification, including `DigestValue` and `SignatureValue`. RSA PKCS#1 v1.5 signatures are deterministic, which makes this possible.
- **Real responses:** the client tests replay acknowledgements recorded from the playground, signed by the Financial Administration.
- **Live playground:** `test-playground` sends real messages to the playground with the shared test certificates in `testdata`.
