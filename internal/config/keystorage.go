package config

import (
	"github.com/go-oidfed/lib/jwx/keymanagement/kms"
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
	}
}
