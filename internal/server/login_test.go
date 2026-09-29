package server

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-oidfed/offa/internal/config"
)

// initTestConfig seeds a minimal throwaway config.yaml in the test working
// directory and loads it via config.MustLoadConfig so config.Get() returns a
// non-nil *Config (config.conf is unexported and only set by MustLoadConfig).
// The yaml seeds one external service so its (unexported-typed) Services slice
// is populated; the external fields themselves are mutated in-place by each
// test.
func initTestConfig(t *testing.T) {
	t.Helper()
	keysDir := t.TempDir()
	cfgPath := filepath.Join(".", "config.yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		t.Fatalf("refusing to overwrite existing %s", cfgPath)
	}
	cfg := []byte(
		"signing:\n" +
			"  key_storage: " + keysDir + "\n" +
			"federation:\n" +
			"  entity_id: https://example.org\n" +
			"op_discovery:\n" +
			"  external:\n" +
			"    enabled: true\n" +
			"    services:\n" +
			"      - url: https://ds.example.org/discovery\n" +
			"        include_entity_id: false\n" +
			"        button:\n" +
			"          text: Discover via Example DS\n",
	)
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		t.Fatalf("write throwaway config.yaml: %v", err)
	}
	t.Cleanup(func() { os.Remove(cfgPath) })
	config.MustLoadConfig()
}

func TestBuildExternalButtons(t *testing.T) {
	initTestConfig(t)
	entityID := "https://offa.example.org"
	config.Get().Federation.EntityID = entityID

	setService := func(t *testing.T, svcURL string, includeEntityID bool) {
		t.Helper()
		ext := &config.Get().OPDiscovery.External
		ext.Enabled = true
		ext.Services[0].URL = svcURL
		ext.Services[0].IncludeEntityID = includeEntityID
		ext.Services[0].Button.Text = "Discover via Example DS"
	}

	t.Run("include_entity_id true merges params", func(t *testing.T) {
		// Pre-existing query param on the service URL must be preserved.
		setService(t, "https://ds.example.org/discovery?existing=1", true)
		next := "https://rp.example.org/login?target_link_uri=abc"

		buttons := buildExternalButtons(next)
		if len(buttons) != 1 {
			t.Fatalf("expected 1 button, got %d", len(buttons))
		}
		href := buttons[0].Href
		q := urlValue(t, href)
		if got := q.Get("existing"); got != "1" {
			t.Fatalf("expected pre-existing query param preserved, got %q: %s", got, href)
		}
		if got := q.Get("target_link_uri"); got != next {
			t.Fatalf("target_link_uri: got %q want %q", got, next)
		}
		if got := q.Get("entityID"); got != entityID {
			t.Fatalf("entityID: got %q want %q", got, entityID)
		}
		if buttons[0].Text != "Discover via Example DS" {
			t.Fatalf("text: got %q", buttons[0].Text)
		}
	})

	t.Run("include_entity_id false omits entityID", func(t *testing.T) {
		setService(t, "https://ds.example.org/discovery", false)
		next := "https://rp.example.org/login"

		buttons := buildExternalButtons(next)
		if len(buttons) != 1 {
			t.Fatalf("expected 1 button, got %d", len(buttons))
		}
		href := buttons[0].Href
		q := urlValue(t, href)
		if got := q.Get("target_link_uri"); got != next {
			t.Fatalf("target_link_uri: got %q want %q", got, next)
		}
		if q.Has("entityID") {
			t.Fatalf("entityID must be absent, got %q in %s", q.Get("entityID"), href)
		}
	})

	t.Run("disabled external renders no buttons", func(t *testing.T) {
		config.Get().OPDiscovery.External.Enabled = false
		if buttons := buildExternalButtons("next"); len(buttons) != 0 {
			t.Fatalf("expected no buttons when disabled, got %d", len(buttons))
		}
		config.Get().OPDiscovery.External.Enabled = true
	})
}

// urlValue returns the query-values map of href's raw query string.
func urlValue(t *testing.T, href string) *url.Values {
	t.Helper()
	u, err := url.Parse(href)
	if err != nil {
		t.Fatalf("parse href %q: %v", href, err)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		t.Fatalf("parse query of %q: %v", href, err)
	}
	return &q
}
