package internal

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/kms"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/zachmann/go-utils/fileutils"

	"github.com/go-oidfed/offa/internal/config"
)

var (
	oidcSigner       jwx.VersatileSigner
	federationSigner jwx.VersatileSigner
)

func migrateLegacyKeys(storagePath string) {
	// 1. Migrate Public Keys Metadata (keys.jwks -> typeID_public.json)
	legacyJwksPath := filepath.Join(storagePath, "keys.jwks")
	if fileutils.FileExists(legacyJwksPath) {
		for _, typeID := range []string{"oidc", "federation"} {
			log.Printf("Found legacy keys.jwks, migrating public keys for %s...", typeID)
			pks, err := public.NewFilesystemPublicKeyStorageFromLegacy(storagePath, typeID)
			if err != nil {
				log.Fatalf("Failed to migrate legacy public keys for %s: %v", typeID, err)
			}
			legacyHistoryPath := filepath.Join(storagePath, fmt.Sprintf("%s_history.jwks", typeID))
			if fileutils.FileExists(legacyHistoryPath) {
				_ = os.Rename(legacyHistoryPath, legacyHistoryPath+".migrated")
			}
			_ = pks // public keys are now persisted to the new format internally
		}
		// Rename the old keys.jwks so it isn't parsed again
		_ = os.Rename(legacyJwksPath, legacyJwksPath+".migrated")
	}

	// 2. Migrate Private Keys (typeID_alg.pem and typeID_algf.pem -> kid.pem)
	for _, typeID := range []string{"oidc", "federation"} {
		for _, aStr := range jwx.SupportedAlgsStrings() {
			alg, ok := jwa.LookupSignatureAlgorithm(aStr)
			if !ok {
				continue // invalid algorithm
			}

			// Check both regular and 'f' variants
			for _, suffix := range []string{"", "f"} {
				legacyPrivKeyPath := filepath.Join(storagePath, fmt.Sprintf("%s_%s%s.pem", typeID, alg.String(), suffix))
				if !fileutils.FileExists(legacyPrivKeyPath) {
					continue
				}

				log.Printf("Found legacy private key %s, migrating...", legacyPrivKeyPath)
				signer, err := jwx.ReadSignerFromFile(legacyPrivKeyPath, alg)
				if err != nil {
					log.Fatalf("Failed to read legacy private key %s: %v", legacyPrivKeyPath, err)
				}

				// Calculate the kid
				_, kid, err := jwx.SignerToPublicJWK(signer, alg)
				if err != nil {
					log.Fatalf("Failed to derive kid for legacy private key %s: %v", legacyPrivKeyPath, err)
				}

				// Write to new path {kid}.pem
				newPrivKeyPath := filepath.Join(storagePath, fmt.Sprintf("%s.pem", kid))
				if !fileutils.FileExists(newPrivKeyPath) {
					if err := jwx.WriteSignerToFile(signer, newPrivKeyPath); err != nil {
						log.Fatalf("Failed to write migrated private key %s: %v", newPrivKeyPath, err)
					}
				}

				// Rename the old file so it's not processed again
				_ = os.Rename(legacyPrivKeyPath, legacyPrivKeyPath+".migrated")
			}
		}
	}
}

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

	// Migrate legacy keys if present
	migrateLegacyKeys(conf.KeyStorage)

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
