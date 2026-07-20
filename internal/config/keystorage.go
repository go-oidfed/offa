package config

import (
	"strings"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/kms"

	log "github.com/go-oidfed/offa/internal/logger"
)

type KeyStorageConf struct {
	GenerateKeys bool                  `yaml:"generate_keys"`
	Alg          string                `yaml:"alg"` // Legacy fallback
	Algs         []string              `yaml:"algs"`
	DefaultAlg   string                `yaml:"default_alg"`
	RSAKeyLen    int                   `yaml:"rsa_key_len"`
	KeyRotation  kms.KeyRotationConfig `yaml:"automatic_key_rollover"`
}

func (c *KeyStorageConf) normalize() {
	if c.Alg != "" {
		if c.DefaultAlg == "" {
			c.DefaultAlg = c.Alg
		}
		if len(c.Algs) == 0 {
			c.Algs = []string{c.Alg}
		}
	} else if len(c.Algs) == 0 {
		c.Algs = jwx.DefaultAlgsStrings()
	}
}

// validateAlgs verifies that every configured algorithm (and the default
// algorithm) is part of the set supported by the go-oidfed library. It returns
// the set of supported algorithms as a lookup helper. Unknown algorithms are
// fatal because they would otherwise only fail later, deep in the KMS setup,
// with a much less actionable error message.
func (c *KeyStorageConf) validateAlgs(section string) {
	supported := make(map[string]struct{}, len(jwx.SupportedAlgsStrings()))
	for _, a := range jwx.SupportedAlgsStrings() {
		supported[a] = struct{}{}
	}
	check := func(alg string) {
		if alg == "" {
			return
		}
		if _, ok := supported[alg]; !ok {
			log.Fatalf(
				"signing.%s: unsupported signing algorithm '%s'; supported algorithms are: %s",
				section, alg, strings.Join(jwx.SupportedAlgsStrings(), ", "),
			)
		}
	}
	for _, a := range c.Algs {
		check(a)
	}
	check(c.DefaultAlg)
}
