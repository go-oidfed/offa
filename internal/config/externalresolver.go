package config

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// externalResolverStrategy selects the fallback strategy for the external
// resolve endpoint resolver.
type externalResolverStrategy string

const (
	// ExternalResolverStrategySmart tries the configured resolve endpoints, then
	// falls back to smart (per-trust-anchor) resolving and finally local
	// resolving.
	ExternalResolverStrategySmart externalResolverStrategy = "smart"
	// ExternalResolverStrategyStrict only uses the configured resolve endpoints
	// and propagates the last error when none succeeds.
	ExternalResolverStrategyStrict externalResolverStrategy = "strict"
)

// against a configured resolve endpoint (POST).
type externalResolverClientAuth struct {
	// Enabled, when true, always authenticates to the endpoint with a
	// private_key_jwt client assertion (Force mode), regardless of what the
	// endpoint's Entity Configuration advertises.
	Enabled bool `yaml:"enabled"`
}

// externalResolverEntry is a single explicit resolve endpoint URL with optional
// client authentication.
type externalResolverEntry struct {
	URL string `yaml:"url"`
	// ClientAuth configures private_key_jwt client authentication for this
	// endpoint.
	ClientAuth externalResolverClientAuth `yaml:"client_auth"`
}

// externalResolverConf configures the external federation resolve endpoint.
// The legacy federation.use_resolve_endpoint boolean is normalized into Enabled
// in MustLoadConfig; when both are set the explicit object's Enabled wins.
type externalResolverConf struct {
	Enabled   bool                     `yaml:"enabled"`
	Strategy  externalResolverStrategy `yaml:"strategy"`
	Endpoints []externalResolverEntry  `yaml:"endpoints"`

	// present records whether the external_resolver key appeared in the YAML at
	// all, so normalization can distinguish "object absent" (legacy bool
	// applies) from "object present with enabled: false" (object wins).
	present bool `yaml:"-"`
}

// UnmarshalYAML implements yaml.Unmarshaler. It records the key's presence and
// decodes the plain struct fields.
func (c *externalResolverConf) UnmarshalYAML(value *yaml.Node) error {
	c.present = true
	type plain externalResolverConf
	return value.Decode((*plain)(c))
}

// validate checks the external resolver configuration: strategy must be known,
// and each non-empty endpoint must have a URL, with duplicate URLs rejected.
func (c externalResolverConf) validate() error {
	switch c.Strategy {
	case "", ExternalResolverStrategySmart, ExternalResolverStrategyStrict:
		// ok
	default:
		return errors.Errorf(
			"federation.external_resolver.strategy %q is invalid; supported: smart, strict",
			c.Strategy,
		)
	}
	seen := make(map[string]struct{}, len(c.Endpoints))
	for _, e := range c.Endpoints {
		if e.URL == "" {
			return errors.New("federation.external_resolver.endpoints: url is required for each endpoint")
		}
		if _, ok := seen[e.URL]; ok {
			return errors.Errorf("federation.external_resolver.endpoints: duplicate url %q", e.URL)
		}
		seen[e.URL] = struct{}{}
	}
	return nil
}
