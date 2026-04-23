package model

import (
	"bytes"
	"encoding/json"
	"strings"
)

type Claim string

// UserClaims holds claims about a user
type UserClaims map[Claim]any

func (claims *UserClaims) UnmarshalJSON(data []byte) error {
	var m map[Claim]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return err
	}
	*claims = m
	return nil
}

func (claims UserClaims) GetForHeader(claim Claim) (string, bool) {
	return claims.getAsString(claim, ",")
}
func (claims UserClaims) GetForMemCache(claim Claim) (string, bool) {
	return claims.getAsString(claim, ":")
}

func (claims UserClaims) getAsString(claim Claim, sliceSeparator string) (string, bool) {
	v, ok := claims.GetString(claim)
	if ok {
		return v, true
	}
	vs, ok := claims.GetStringSlice(claim)
	if ok {
		return strings.Join(vs, sliceSeparator), true
	}
	return "", false
}

func (claims UserClaims) GetString(claim Claim) (string, bool) {
	v, ok := claims[claim]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (claims UserClaims) GetStringSlice(claim Claim) ([]string, bool) {
	v, ok := claims[claim]
	if !ok {
		return nil, false
	}
	s, ok := v.([]string)
	return s, ok
}
