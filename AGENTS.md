# AGENTS.md

Guidance for coding agents and contributors working on this repository.

## Public repository

This repository is public. Never add anything that is not about EET 2.0 itself:

- no names of other services, repositories, products, customers or people;
- no internal URLs, hostnames, ticket IDs, infrastructure details or secrets;
- test data comes only from public EET material (the official samples and the shared playground certificates published at https://eet.gov.cz) or is synthetic.

Check every change for this before pushing, including commit messages and pull request descriptions.

## Source of truth

The implementation follows the official EET 2.0 documents from https://eet.gov.cz/cs/pro-vyvojare/dokumenty-ke-stazeni: the data interface description, `EETXMLSchema.xsd`, `EETServiceSOAP.wsdl`, the item descriptions with examples, the access and operational information for the playground and production, and the CA EET certificate procedures with `caeetapi_jwt.yml`. When behaviour is unclear, check those documents and the live playground, not assumptions.

## Layout

| Path | Contents |
| --- | --- |
| `eet/` | Public EET client: data model and validation (`sale.go`, `amount.go`, `datetime.go`, `lint.go`), message header and envelope (`header.go`, `envelope.go`, `signer.go`), sending (`client.go`, `options.go`, `message.go`), responses and errors (`response.go`, `errors.go`) |
| `caeet/` | Public CA EET API client: `client.go`, `token.go`, `requests.go`, `renew.go`, `errors.go` |
| `internal/wssec/` | WS-Security: signed SOAP envelope (`sign.go`), signature verification (`verify.go`), XML rendering (`xml.go`); knows nothing about EET |
| `internal/fixtures/` | Embedded test data shared by all packages: official sample requests, shared playground certificates, recorded playground responses |
| `scripts/` | CI helpers |

One file has one responsibility. Put new code in the file whose responsibility it shares, and add a file only for a new responsibility. Tests live next to the code they test, in the same package, as `*_test.go` files. `internal/fixtures` may be imported only from tests.

## Code conventions

- No comments in code.
- Extract magic values (timeouts, limits, codes, algorithm URIs) to named constants at the top of the file.
- Never have consecutive parameters of the same type; use a struct or a distinct type instead.
- Functions must not mutate their arguments; build and return new values.
- Never discard errors silently.
- No test-only code paths in the library: no package-level variables or options that exist only so tests can inject fakes.
- The request envelope must stay byte-for-byte identical to the official samples; `TestBuildEnvelope` enforces this.
- Response data is read only from the signed SOAP Body.

## Tests

- One table-driven `TestXxx` per operation: `for _, tc := range []struct{ name string; ... }{...}` with `t.Run(tc.name, ...)`, never copy-pasted subtests.
- Every top-level test and subtest calls `t.Parallel()`.
- Every validation rule has its own row asserting the field and the error reason.
- Assert outcomes, not implementation details.
- Use `httptest` servers for HTTP; never call `t.Fatal` from a handler goroutine, report with `t.Error` instead.
- Signed playground responses in `internal/fixtures` are real. To reuse one, prepare a message and set its `UUID` to the response's `uuid_zpravy`.

Test strategy:

- **Byte-for-byte check:** `TestBuildEnvelope` rebuilds the three official sample requests, including `DigestValue` and `SignatureValue`. RSA PKCS#1 v1.5 signatures are deterministic, which makes this possible.
- **Real responses:** client tests replay acknowledgements recorded from the playground, signed by the Financial Administration.
- **Live playground:** the `playground` build tag sends real messages to the playground with the shared test certificates.

## Commands

```bash
make lint
```

```bash
make test
```

```bash
make test-coverage
```

```bash
make vulncheck
```

```bash
make test-playground
```

`make lint` runs gofmt, `go fix -diff`, `go vet` and `go mod tidy -diff`, with and without the `playground` tag. It must pass before every push.

## CI and releases

- `.github/workflows/ci.yml` runs lint, govulncheck, unit tests with `-race` and coverage on pull requests and pushes to `main`.
- After all checks pass on `main`, the release job tags the next patch version with `scripts/next-version.sh`, creates a GitHub Release with generated notes and fetches the version through `proxy.golang.org`.
- Pushes that change no Go code (`*.go`, `go.mod`, `go.sum`) are not released.
- Run the CI workflow manually and choose `minor` or `major` to release a bigger version.
- Never move or delete a published tag: the Go checksum database has recorded it.
- `.github/workflows/playground.yml` runs the live playground suite weekly and on demand. It is not a required check, because the playground has a maintenance window on Thursdays from 20:00 to 06:00.
- Dependabot keeps Go modules and GitHub Actions up to date.
