package env

import (
	_ "embed"
	"encoding/json"

	"github.com/cubist-labs/cubesigner-go-sdk/session"
)

var (
	// CubeSigner Beta deployment
	Beta session.EnvInterface
	// CubeSigner Gamma deployment
	Gamma session.EnvInterface
	// CubeSigner Production deployment
	Prod session.EnvInterface
)

// embed at build time
//
//go:embed beta.json
var beta []byte

//go:embed gamma.json
var gamma []byte

//go:embed prod.json
var prod []byte

func init() {
	// parse into exported EnvInterfaces when spec is imported
	err := json.Unmarshal(beta, &Beta)
	assertNil(err)
	err = json.Unmarshal(gamma, &Gamma)
	assertNil(err)
	err = json.Unmarshal(prod, &Prod)
	assertNil(err)
}

func assertNil(err error) {
	if err != nil {
		panic(err)
	}
}
