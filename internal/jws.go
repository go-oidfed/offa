package internal

import (
	"log"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/kms"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/go-oidfed/offa/internal/config"
)

var (
	oidcSigner       jwx.VersatileSigner
	federationSigner jwx.VersatileSigner
)

func createVersatileSigner(storagePath string, typeID string, c config.KeyStorageConf) jwx.VersatileSigner {
	algs := make([]jwa.SignatureAlgorithm, 0, len(c.Algs))
	for _, a := range c.Algs {
		alg, ok := jwa.LookupSignatureAlgorithm(a)
		if !ok {
			log.Fatalf("invalid algorithm %s", a)
		}
		algs = append(algs, alg)
	}

	defaultAlg, ok := jwa.LookupSignatureAlgorithm(c.DefaultAlg)
	if !ok {
		log.Fatalf("invalid default algorithm %s", c.DefaultAlg)
	}

	k, err := kms.NewFilesystemKMSAndPublicKeyStorage(kms.FilesystemKMSConfig{
		KMSConfig: kms.KMSConfig{
			GenerateKeys: c.GenerateKeys,
			Algs:         algs,
			DefaultAlg:   defaultAlg,
			RSAKeyLen:    c.RSAKeyLen,
			KeyRotation:  c.KeyRotation,
		},
		Dir:    storagePath,
		TypeID: typeID,
	})
	if err != nil {
		log.Fatal(err)
	}

	return kms.KMSToVersatileSignerWithPKStorage(k, k.(*kms.FilesystemKMS).PKs)
}

func createSingleAlgVersatileSigner(storagePath string, typeID string, c config.KeyStorageConf) jwx.VersatileSigner {
	if len(c.Algs) != 1 {
		log.Fatalf("expected exactly one algorithm for %s, got %d", typeID, len(c.Algs))
	}
	a := c.Algs[0]
	alg, ok := jwa.LookupSignatureAlgorithm(a)
	if !ok {
		log.Fatalf("invalid algorithm %s", a)
	}

	defaultAlg, ok := jwa.LookupSignatureAlgorithm(c.DefaultAlg)
	if !ok {
		log.Fatalf("invalid default algorithm %s", c.DefaultAlg)
	}

	pks := &public.FilesystemPublicKeyStorage{
		Dir:    storagePath,
		TypeID: typeID,
	}
	if err := pks.Load(); err != nil {
		log.Fatal(err)
	}

	k := kms.NewSingleAlgFilesystemKMS(alg, kms.FilesystemKMSConfig{
		KMSConfig: kms.KMSConfig{
			GenerateKeys: c.GenerateKeys,
			DefaultAlg:   defaultAlg,
			RSAKeyLen:    c.RSAKeyLen,
			KeyRotation:  c.KeyRotation,
		},
		Dir:    storagePath,
		TypeID: typeID,
	}, pks)
	if err := k.Load(); err != nil {
		log.Fatal(err)
	}

	return kms.KMSToVersatileSignerWithPKStorage(k, pks)
}

// InitKeys initialized the signing keys
func InitKeys() {
	conf := config.Get().Signing

	oidcSigner = createVersatileSigner(conf.KeyStorage, "oidc", conf.OIDC)
	federationSigner = createSingleAlgVersatileSigner(conf.KeyStorage, "federation", conf.Federation)
}

// OIDCSigner returns the oidc jwx.VersatileSigner
func OIDCSigner() jwx.VersatileSigner {
	return oidcSigner
}

// FederationSigner returns the federation jwx.VersatileSigner
func FederationSigner() jwx.VersatileSigner {
	return federationSigner
}
