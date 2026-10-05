package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeTestConfig seeds a throwaway config.yaml in the test working directory
// and loads it via MustLoadConfig. The caller must not have a config.yaml in
// the working directory already (mirrors internal/server/login_test.go).
func writeTestConfig(t *testing.T, cfg string) {
	t.Helper()
	cfgPath := filepath.Join(".", "config.yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		t.Fatalf("refusing to overwrite existing %s", cfgPath)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write throwaway config.yaml: %v", err)
	}
	t.Cleanup(func() { os.Remove(cfgPath) })
	MustLoadConfig()
}

func TestExternalResolverConf_Decode(t *testing.T) {
	var c externalResolverConf
	src := `
enabled: true
strategy: strict
endpoints:
  - url: https://resolve1.example.com/resolve
    client_auth:
      enabled: true
  - url: https://resolve2.example.com/resolve
`
	if err := yaml.Unmarshal([]byte(src), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !c.Enabled {
		t.Fatalf("enabled: %v", c.Enabled)
	}
	if c.Strategy != ExternalResolverStrategyStrict {
		t.Fatalf("strategy: %q", c.Strategy)
	}
	if len(c.Endpoints) != 2 {
		t.Fatalf("endpoints: %d", len(c.Endpoints))
	}
	if c.Endpoints[0].URL != "https://resolve1.example.com/resolve" || !c.Endpoints[0].ClientAuth.Enabled {
		t.Fatalf("endpoint 0: %+v", c.Endpoints[0])
	}
	if c.Endpoints[1].ClientAuth.Enabled {
		t.Fatalf("endpoint 1 should have client auth disabled: %+v", c.Endpoints[1])
	}
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestExternalResolverConf_ValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		conf externalResolverConf
	}{
		{
			name: "bogus strategy",
			conf: externalResolverConf{Enabled: true, Strategy: "bogus"},
		},
		{
			name: "empty endpoint url",
			conf: externalResolverConf{
				Enabled:   true,
				Endpoints: []externalResolverEntry{{URL: ""}},
			},
		},
		{
			name: "duplicate endpoint urls",
			conf: externalResolverConf{
				Enabled: true,
				Endpoints: []externalResolverEntry{
					{URL: "https://a.example/resolve"}, {URL: "https://a.example/resolve"},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.conf.validate(); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
	// Empty strategy is fine (normalized to smart).
	if err := (externalResolverConf{Enabled: true}).validate(); err != nil {
		t.Fatalf("empty strategy should validate: %v", err)
	}
}

func TestExternalResolver_LegacyBoolNormalization(t *testing.T) {
	keysDir := t.TempDir()
	writeTestConfig(t, "signing:\n"+
		"  key_storage: "+keysDir+"\n"+
		"federation:\n"+
		"  entity_id: https://example.org\n"+
		"  use_resolve_endpoint: true\n")
	c := Get()
	if !c.Federation.ExternalResolver.Enabled {
		t.Fatalf("legacy use_resolve_endpoint should normalize to ExternalResolver.Enabled=true")
	}
	if c.Federation.ExternalResolver.Strategy != ExternalResolverStrategySmart {
		t.Fatalf("strategy should default to smart, got %q", c.Federation.ExternalResolver.Strategy)
	}
}

func TestExternalResolver_ObjectWinsOverLegacyBool(t *testing.T) {
	keysDir := t.TempDir()
	writeTestConfig(t, "signing:\n"+
		"  key_storage: "+keysDir+"\n"+
		"federation:\n"+
		"  entity_id: https://example.org\n"+
		"  use_resolve_endpoint: true\n"+
		"  external_resolver:\n"+
		"    enabled: false\n")
	if Get().Federation.ExternalResolver.Enabled {
		t.Fatalf("explicit external_resolver.enabled=false must win over legacy bool")
	}
}

func TestExternalResolver_FullObjectNormalization(t *testing.T) {
	keysDir := t.TempDir()
	writeTestConfig(t, "signing:\n"+
		"  key_storage: "+keysDir+"\n"+
		"federation:\n"+
		"  entity_id: https://example.org\n"+
		"  external_resolver:\n"+
		"    enabled: true\n"+
		"    strategy: strict\n"+
		"    endpoints:\n"+
		"      - url: https://resolve.example.com/resolve\n"+
		"        client_auth:\n"+
		"          enabled: true\n")
	c := Get()
	if !c.Federation.ExternalResolver.Enabled {
		t.Fatalf("enabled should be true")
	}
	if c.Federation.ExternalResolver.Strategy != ExternalResolverStrategyStrict {
		t.Fatalf("strategy: %q", c.Federation.ExternalResolver.Strategy)
	}
	if len(c.Federation.ExternalResolver.Endpoints) != 1 {
		t.Fatalf("endpoints: %d", len(c.Federation.ExternalResolver.Endpoints))
	}
	if !c.Federation.ExternalResolver.Endpoints[0].ClientAuth.Enabled {
		t.Fatalf("client_auth.enabled should be true")
	}
}

func TestExternalResolver_BogusStrategyFailsMustLoad(t *testing.T) {
	// MustLoadConfig log.Fatals on validation errors; instead verify via the
	// validate() entry point that the strategy reaches validation intact.
	prev := conf
	conf = &Config{}
	conf.Federation.ExternalResolver = externalResolverConf{
		Enabled:  true,
		Strategy: "bogus",
	}
	t.Cleanup(func() { conf = prev })
	if err := validate(); err == nil {
		t.Fatalf("expected validation error for bogus strategy")
	}
}
