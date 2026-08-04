package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestAuthorityHintList_StringForm(t *testing.T) {
	var l AuthorityHintList
	src := `
- https://ta1.example.com
- https://ta2.example.com
`
	if err := yaml.Unmarshal([]byte(src), &l); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(l) != 2 || l[0].EntityID != "https://ta1.example.com" {
		t.Fatalf("unexpected: %+v", l)
	}
	if l[0].JWKSSync.Mode != "" {
		t.Fatalf("expected empty mode, got %q", l[0].JWKSSync.Mode)
	}
	if got := l.EntityIDs(); len(got) != 2 || got[1] != "https://ta2.example.com" {
		t.Fatalf("EntityIDs: %v", got)
	}
	if l.HasSyncMode() {
		t.Fatalf("HasSyncMode should be false")
	}
	if err := l.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestAuthorityHintList_ObjectForm(t *testing.T) {
	var l AuthorityHintList
	src := `
- entity_id: https://ta1.example.com
- entity_id: https://ta2.example.com
  jwks_sync:
    mode: push
    jwt_lifetime: 5m
    timeout: 10s
    headers:
      X-Custom: value
- entity_id: https://ta3.example.com
  jwks_sync:
    mode: trigger
`
	if err := yaml.Unmarshal([]byte(src), &l); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(l) != 3 {
		t.Fatalf("len: %d", len(l))
	}
	if l[1].JWKSSync.Mode != JWKSSyncPush {
		t.Fatalf("mode: %q", l[1].JWKSSync.Mode)
	}
	if d := l[1].JWKSSync.JWTLifetime.Duration(); d != 5*time.Minute {
		t.Fatalf("jwt_lifetime: %v", d)
	}
	if d := l[1].JWKSSync.Timeout.Duration(); d != 10*time.Second {
		t.Fatalf("timeout: %v", d)
	}
	if l[1].JWKSSync.Headers["X-Custom"] != "value" {
		t.Fatalf("headers: %v", l[1].JWKSSync.Headers)
	}
	if l[2].JWKSSync.Mode != JWKSSyncTrigger {
		t.Fatalf("mode: %q", l[2].JWKSSync.Mode)
	}
	if !l.HasSyncMode() {
		t.Fatalf("HasSyncMode should be true")
	}
	if err := l.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestAuthorityHintList_MixedForm(t *testing.T) {
	var l AuthorityHintList
	src := `
- https://ta1.example.com
- entity_id: https://ta2.example.com
  jwks_sync:
    mode: none
`
	if err := yaml.Unmarshal([]byte(src), &l); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if l[0].EntityID != "https://ta1.example.com" || l[1].EntityID != "https://ta2.example.com" {
		t.Fatalf("unexpected: %+v", l)
	}
	if l.HasSyncMode() {
		t.Fatalf("HasSyncMode should be false")
	}
	if err := l.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestAuthorityHintList_ValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"missing entity_id", `
- jwks_sync:
    mode: push
`},
		{"duplicate entity_id", `
- https://ta.example.com
- entity_id: https://ta.example.com
`},
		{"unknown mode", `
- entity_id: https://ta.example.com
  jwks_sync:
    mode: bogus
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var l AuthorityHintList
			if err := yaml.Unmarshal([]byte(tt.src), &l); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if err := l.validate(); err == nil {
				t.Fatalf("expected validation error, got nil")
			}
		})
	}
}

func TestAuthorityHintList_DefaultDurationOption(t *testing.T) {
	var l AuthorityHintList
	src := `
- entity_id: https://ta.example.com
  jwks_sync:
    mode: push
`
	if err := yaml.Unmarshal([]byte(src), &l); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d := l[0].JWKSSync.JWTLifetime.Duration(); d != 0 {
		t.Fatalf("expected zero default, got %v", d)
	}
}
