package internal

import (
	"log"

	"github.com/go-oidfed/lib/jwx"

	"github.com/go-oidfed/offa/internal/config"
)

var keys *jwx.KeyStorage

// InitKeys initialized the signing keys
func InitKeys() {
	conf := config.Get().Signing
	var err error
	keys, err = jwx.NewKeyStorage(
		conf.KeyStorage,
		map[string]jwx.KeyStorageConfig{
			jwx.KeyStorageTypeFederation: conf.Federation,
			jwx.KeyStorageTypeOIDC:       conf.OIDC,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	err = keys.Load()
	if err != nil {
		log.Fatal(err)
	}
}

// OIDCSigner returns the oidc jwx.VersatileSigner
func OIDCSigner() jwx.VersatileSigner {
	return keys.OIDC()
}

// FederationSigner returns the federation jwx.VersatileSigner
func FederationSigner() jwx.VersatileSigner {
	return keys.Federation()
}
