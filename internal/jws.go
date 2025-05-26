package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/zachmann/go-oidfed/pkg/jwk"

	"github.com/zachmann/offa/internal/config"
)

const FedSigningKeyName = "fed.signing.key"
const OIDCSigningKeyName = "oidc.signing.key"

func mustNewKey() *ecdsa.PrivateKey {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

func mustLoadKey(name string) crypto.Signer {
	data, err := os.ReadFile(path.Join(config.Get().Federation.KeyStorage, name))
	if err != nil {
		sk := mustNewKey()
		if err = os.WriteFile(
			path.Join(config.Get().Federation.KeyStorage, name), exportECPrivateKeyAsPem(sk), 0600,
		); err != nil {
			log.Fatal(err)
		}
		return sk
	}
	block, _ := pem.Decode(data)
	sk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

var keys map[string]crypto.Signer
var jwks map[string]jwk.JWKS

func InitKeys(names ...string) {
	keys = make(map[string]crypto.Signer)
	jwks = make(map[string]jwk.JWKS)
	for _, name := range names {
		keys[name] = mustLoadKey(name)
		set := jwk.KeyToJWKS(keys[name].Public(), jwa.ES512())
		jwks[name] = set
	}
}

func GetKey(name string) crypto.Signer {
	return keys[name]
}
func GetJWKS(name string) *jwk.JWKS {
	set := jwks[name]
	return &set
}

func exportECPrivateKeyAsPem(privkey *ecdsa.PrivateKey) []byte {
	privkeyBytes, _ := x509.MarshalECPrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem
}
