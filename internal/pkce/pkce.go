package pkce

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"

	log "github.com/go-oidfed/offa/internal/logger"
)

// PKCE is a type holding the information for a PKCE flow
type PKCE struct {
	verifier  string
	challenge string
	method    Method
}

type marshalAlias struct {
	Verifier  string
	Challenge string
	Method    Method
}

// MarshalMsgpack implements the msgpack.Marshaler interface
func (pkce PKCE) MarshalMsgpack() ([]byte, error) {
	data, err := msgpack.Marshal(
		marshalAlias{
			Verifier:  pkce.verifier,
			Challenge: pkce.challenge,
			Method:    pkce.method,
		},
	)
	if err != nil {
		log.WithError(err).Error("error marshalling PKCE alias")
	}
	return data, err
}

// UnmarshalMsgpack implements the msgpack.Unmarshaler interface
func (pkce *PKCE) UnmarshalMsgpack(data []byte) error {
	var alias marshalAlias
	if err := msgpack.Unmarshal(data, &alias); err != nil {
		log.WithError(err).Error("error unmarshalling alias")
		return errors.WithStack(err)
	}
	*pkce = PKCE{
		verifier:  alias.Verifier,
		challenge: alias.Challenge,
		method:    alias.Method,
	}
	return nil
}

// Method is a type for the code challenge methods
type Method string

// Defines for the possible Method
const (
	TransformationPlain = Method("plain")
	TransformationS256  = Method("S256")
)

func (m Method) String() string {
	return string(m)
}

// NewPKCE creates a new PKCE for the passed verifier and Method
func NewPKCE(verifier string, method Method) *PKCE {
	return &PKCE{
		verifier: verifier,
		method:   method,
	}
}

// NewS256PKCE creates a new PKCE for the passed verifier and the Method TransformationS256
func NewS256PKCE(verifier string) *PKCE {
	return NewPKCE(verifier, TransformationS256)
}

// Verifier returns the code_verifier
func (pkce PKCE) Verifier() string {
	return pkce.verifier
}

// Challenge returns the code_challenge according to the defined Method
func (pkce *PKCE) Challenge() (string, error) {
	var err error
	if pkce.challenge == "" {
		pkce.challenge, err = pkce.transform()
	}
	return pkce.challenge, err
}

func (pkce PKCE) transform() (string, error) {
	switch pkce.method {
	case TransformationPlain:
		return pkce.plain(), nil
	case TransformationS256:
		return pkce.s256(), nil
	default:
		return "", errors.New("unknown code_challenge_method")
	}
}

func (pkce PKCE) plain() string {
	return pkce.verifier
}

func (pkce PKCE) s256() string {
	hash := sha256.Sum256([]byte(pkce.verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}

func (pkce PKCE) Method() Method {
	return pkce.method
}
