package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"

	"github.com/go-oidfed/lib"
	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/offa/internal/config"
)

// setupResolverTest seeds a throwaway config.yaml, loads it, and installs a
// test federation signer so SetupMetadataResolver can build its producer
// without touching the real KMS.
func setupResolverTest(t *testing.T, federationYAML string) {
	t.Helper()
	cfgPath := filepath.Join(".", "config.yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		t.Fatalf("refusing to overwrite existing %s", cfgPath)
	}
	keysDir := t.TempDir()
	cfg := "signing:\n" +
		"  key_storage: " + keysDir + "\n" +
		"federation:\n" +
		"  entity_id: https://offa.example.org\n" +
		federationYAML
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write throwaway config.yaml: %v", err)
	}
	t.Cleanup(func() { os.Remove(cfgPath) })
	config.MustLoadConfig()

	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	prevSigner := federationSigner
	federationSigner = jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	t.Cleanup(func() { federationSigner = prevSigner })
}

func TestSetupMetadataResolver_Disabled(t *testing.T) {
	setupResolverTest(t, "")
	SetupMetadataResolver()
	if _, ok := oidfed.DefaultMetadataResolver.(oidfed.LocalMetadataResolver); !ok {
		t.Fatalf("expected LocalMetadataResolver, got %T", oidfed.DefaultMetadataResolver)
	}
	if oidfed.DefaultClientAuth != nil {
		t.Fatalf("expected nil DefaultClientAuth when disabled")
	}
}

func TestSetupMetadataResolver_SmartNoEndpoints(t *testing.T) {
	setupResolverTest(t, "  external_resolver:\n"+
		"    enabled: true\n")
	SetupMetadataResolver()
	smart, ok := oidfed.DefaultMetadataResolver.(oidfed.SmartRemoteMetadataResolver)
	if !ok {
		t.Fatalf("expected SmartRemoteMetadataResolver, got %T", oidfed.DefaultMetadataResolver)
	}
	if smart.ClientAuth == nil || smart.ClientAuth.ROProducer == nil {
		t.Fatalf("expected smart resolver with ClientAuth producer")
	}
	if oidfed.DefaultClientAuth == nil {
		t.Fatalf("expected DefaultClientAuth to be set for fetch/list/trust-mark auto-auth")
	}
}

func TestSetupMetadataResolver_CompositeEndpoints(t *testing.T) {
	setupResolverTest(t, "  external_resolver:\n"+
		"    enabled: true\n"+
		"    strategy: strict\n"+
		"    endpoints:\n"+
		"      - url: https://resolve1.example.com/resolve\n"+
		"        client_auth:\n"+
		"          enabled: true\n"+
		"      - url: https://resolve2.example.com/resolve\n")
	SetupMetadataResolver()
	comp, ok := oidfed.DefaultMetadataResolver.(multiEndpointResolver)
	if !ok {
		t.Fatalf("expected multiEndpointResolver, got %T", oidfed.DefaultMetadataResolver)
	}
	if len(comp.endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(comp.endpoints))
	}
	if comp.endpoints[0].ResolveEndpoint != "https://resolve1.example.com/resolve" {
		t.Fatalf("endpoint 0: %q", comp.endpoints[0].ResolveEndpoint)
	}
	if comp.endpoints[0].ClientAuth == nil {
		t.Fatalf("endpoint 0 should have client auth enabled (non-nil producer)")
	}
	if comp.endpoints[1].ClientAuth != nil {
		t.Fatalf("endpoint 1 should have client auth disabled (nil producer)")
	}
	if !comp.strict {
		t.Fatalf("expected strict strategy")
	}
	if comp.fallback.ClientAuth == nil {
		t.Fatalf("expected smart fallback to carry the producer")
	}
	if oidfed.DefaultClientAuth == nil {
		t.Fatalf("expected DefaultClientAuth to be set")
	}

	// Idempotency: calling again yields the same state.
	SetupMetadataResolver()
	if _, ok := oidfed.DefaultMetadataResolver.(multiEndpointResolver); !ok {
		t.Fatalf("expected multiEndpointResolver after re-run, got %T", oidfed.DefaultMetadataResolver)
	}
}

// TestMultiEndpointResolver_EndToEndSmoke boots the full wiring (config ->
// SetupMetadataResolver -> composite resolver) against a local httptest server
// acting as the configured resolve endpoint. With client_auth.enabled: true the
// request must be a form-encoded POST carrying the resolve params plus
// client_assertion_type/client_assertion (aud = endpoint URL); with the strict
// strategy a failing endpoint propagates the error instead of falling back.
func TestMultiEndpointResolver_EndToEndSmoke(t *testing.T) {
	var (
		gotMethod       string
		gotContentType  string
		gotAssertion    string
		gotAssertionTyp string
		gotSub          string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAssertion = r.FormValue("client_assertion")
		gotAssertionTyp = r.FormValue("client_assertion_type")
		gotSub = r.FormValue("sub")
		// Not a valid resolve response -> resolution fails downstream.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("garbage"))
	}))
	defer srv.Close()

	setupResolverTest(t, "  external_resolver:\n"+
		"    enabled: true\n"+
		"    strategy: strict\n"+
		"    endpoints:\n"+
		"      - url: "+srv.URL+"\n"+
		"        client_auth:\n"+
		"          enabled: true\n")
	SetupMetadataResolver()

	_, err := oidfed.DefaultMetadataResolver.ResolveResponsePayload(
		apimodel.ResolveRequest{
			Subject:     "https://op.example.org",
			TrustAnchor: []string{"https://ta.example.org"},
		},
	)
	if err == nil {
		t.Fatalf("expected strict strategy to propagate the endpoint error")
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
	if !strings.Contains(gotContentType, "application/x-www-form-urlencoded") {
		t.Fatalf("expected form content type, got %q", gotContentType)
	}
	if gotAssertionTyp != oidfedconst.OAuthClientAssertionJWTBearer {
		t.Fatalf("client_assertion_type: %q", gotAssertionTyp)
	}
	if gotAssertion == "" {
		t.Fatalf("client_assertion missing")
	}
	if gotSub != "https://op.example.org" {
		t.Fatalf("resolve params missing from form body: sub=%q", gotSub)
	}

	// Verify the assertion claims: issued by OFFA, audience = endpoint URL.
	// The assertion is a JWS compact serialization; decode the payload segment.
	parts := strings.Split(gotAssertion, ".")
	if len(parts) != 3 {
		t.Fatalf("client_assertion is not a JWS compact JWT: %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode assertion payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims["iss"] != "https://offa.example.org" {
		t.Fatalf("iss: %v", claims["iss"])
	}
	if claims["aud"] != srv.URL {
		t.Fatalf("aud: %v", claims["aud"])
	}
}
