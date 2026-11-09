package fixtures

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

const (
	EICLegalEntity   = "CZ00000019"
	EICVCP           = "CZ683555118"
	EICNaturalPerson = "CZ8551015704"

	ResponseSend     = "send"
	ResponseWarnings = "warnings"
	ResponseVerify   = "verify"
	ResponseError    = "error"

	dataDir = "data"
)

//go:embed data
var files embed.FS

func read(name string) []byte {
	b, err := files.ReadFile(path.Join(dataDir, name))
	if err != nil {
		panic(fmt.Sprintf("fixtures: %v", err))
	}
	return b
}

func PlaygroundP12(eic string) []byte {
	return read("CA_EET-Playground-" + eic + ".p12")
}

func PlaygroundPassword() string {
	return strings.TrimSpace(string(read("playground-p12-password.txt")))
}

func SampleRequest(eic string) []byte {
	return read(eic + ".eet.v4.req.xml")
}

func PlaygroundResponse(name string) []byte {
	return read("playground-response-" + name + ".xml")
}
