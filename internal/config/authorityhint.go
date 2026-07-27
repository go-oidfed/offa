package config

import (
	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/duration"
	"gopkg.in/yaml.v3"
)

// JWKSSyncMode selects how (if at all) rotated federation keys are synced to an
// authority hint after a key rotation.
type JWKSSyncMode string

const (
	// JWKSSyncNone disables syncing. This is the default for legacy
	// string-form authority hints.
	JWKSSyncNone JWKSSyncMode = "none"
	// JWKSSyncPush pushes a signed JWK Set (application/jwk-set+jwt) to the
	// authority hint's federation_jwks_update_endpoint. The endpoint URL and
	// acceptable signing algorithms are resolved dynamically from the
	// authority hint's Entity Configuration on each rotation. Corresponds to
	// oidfed.JWKSUpdateHook in the go-oidfed lib.
	JWKSSyncPush JWKSSyncMode = "push"
	// JWKSSyncTrigger POSTs the entity_id to the authority hint's
	// federation_jwks_update_trigger_endpoint (authenticated with
	// private_key_jwt), telling it to re-fetch this entity's JWKS from its
	// Entity Configuration. Corresponds to oidfed.TriggerUpdateHook in the
	// go-oidfed lib.
	JWKSSyncTrigger JWKSSyncMode = "trigger"
)

// JWKSSyncConf configures optional syncing of rotated federation keys to an
// authority hint. It only has an effect when automatic key rollover is enabled
// for the federation signing keys (signing.federation.automatic_key_rollover).
type JWKSSyncConf struct {
	// Mode selects the sync mechanism. Default: none.
	Mode JWKSSyncMode `yaml:"mode"`
	// JWTLifetime is the lifetime (exp - iat) of the signed JWKS JWT sent in
	// push mode. Default: 10 minutes. Ignored in other modes.
	JWTLifetime duration.DurationOption `yaml:"jwt_lifetime"`
	// Timeout is the HTTP client timeout for the sync request. Default: 20s.
	Timeout duration.DurationOption `yaml:"timeout"`
	// Headers are additional HTTP headers set on the sync request.
	Headers map[string]string `yaml:"headers"`
}

// AuthorityHint is a federation authority hint: a direct superior entity that
// issues a statement about OFFA. The optional JWKSSync configures syncing of
// rotated federation keys to this authority hint.
type AuthorityHint struct {
	EntityID string       `yaml:"entity_id"`
	JWKSSync JWKSSyncConf `yaml:"jwks_sync"`
}

// AuthorityHintList is a list of AuthorityHint with a YAML unmarshaler that
// accepts both the legacy plain-string form and the structured object form.
// A plain string is equivalent to an object with entity_id set and
// jwks_sync.mode = "none".
type AuthorityHintList []AuthorityHint

// UnmarshalYAML implements yaml.Unmarshaler. Each item may be either a scalar
// (the entity_id) or a mapping with entity_id and optional jwks_sync.
func (l *AuthorityHintList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode {
		return errors.New("authority_hints: expected a sequence")
	}
	out := make(AuthorityHintList, 0, len(value.Content))
	for _, item := range value.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			var entityID string
			if err := item.Decode(&entityID); err != nil {
				return errors.Wrap(err, "authority_hints: could not decode scalar item")
			}
			out = append(out, AuthorityHint{EntityID: entityID})
		case yaml.MappingNode:
			var ah AuthorityHint
			if err := item.Decode(&ah); err != nil {
				return errors.Wrap(err, "authority_hints: could not decode mapping item")
			}
			out = append(out, ah)
		default:
			return errors.Errorf("authority_hints: unsupported item kind %d", item.Kind)
		}
	}
	*l = out
	return nil
}

// EntityIDs returns the entity IDs of all authority hints.
func (l AuthorityHintList) EntityIDs() []string {
	if len(l) == 0 {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, ah := range l {
		out = append(out, ah.EntityID)
	}
	return out
}

// validate checks the authority hint list for consistency: object-form entries
// must have an entity_id, modes must be known, and entity IDs must be unique.
func (l AuthorityHintList) validate() error {
	seen := make(map[string]struct{}, len(l))
	for _, ah := range l {
		if ah.EntityID == "" {
			return errors.New("authority_hints: entity_id is required for object-form entries")
		}
		if _, ok := seen[ah.EntityID]; ok {
			return errors.Errorf("authority_hints: duplicate entity_id %q", ah.EntityID)
		}
		seen[ah.EntityID] = struct{}{}
		switch ah.JWKSSync.Mode {
		case "", JWKSSyncNone, JWKSSyncPush, JWKSSyncTrigger:
			// ok
		default:
			return errors.Errorf(
				"authority_hints: unknown jwks_sync.mode %q for %q; supported: none, push, trigger",
				ah.JWKSSync.Mode, ah.EntityID,
			)
		}
	}
	return nil
}

// HasSyncMode returns true if any authority hint uses a non-none sync mode.
func (l AuthorityHintList) HasSyncMode() bool {
	for _, ah := range l {
		if ah.JWKSSync.Mode != "" && ah.JWKSSync.Mode != JWKSSyncNone {
			return true
		}
	}
	return false
}
