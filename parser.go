/*
 * Copyright 2023 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package paseto

import (
	"time"

	"aidanwoods.dev/go-paseto"
)

// ParseFunc parse and verify paseto and validate against
// any parser rules. Error if parsing, verification, or any rule fails.
type ParseFunc func(token string) (*paseto.Token, error)

// ParseOption is the only struct that can be used to add rule to ParseFunc.
type ParseOption func(ps *paseto.Parser)

// NewV2LocalParseFunc will return a function which parse and valid v2 local paseto.
func NewV2LocalParseFunc(symmetricKey string, options ...ParseOption) (ParseFunc, error) {
	parser := paseto.NewParser()
	for _, option := range options {
		option(&parser)
	}
	key, err := paseto.V2SymmetricKeyFromHex(symmetricKey)
	if err != nil {
		return nil, nil
	}
	return func(token string) (*paseto.Token, error) {
		return parser.ParseV2Local(key, token)
	}, nil
}

// NewV2PublicParseFunc will return a function which parse and valid v2 public paseto.
func NewV2PublicParseFunc(asymmetricPubKey string, options ...ParseOption) (ParseFunc, error) {
	parser := paseto.NewParser()
	for _, option := range options {
		option(&parser)
	}
	key, err := paseto.NewV2AsymmetricPublicKeyFromHex(asymmetricPubKey)
	if err != nil {
		return nil, nil
	}
	return func(token string) (*paseto.Token, error) {
		return parser.ParseV2Public(key, token)
	}, nil
}

// NewV3LocalParseFunc will return a function which parse and valid v3 local paseto.
func NewV3LocalParseFunc(symmetricPubKey string, implicit []byte, options ...ParseOption) (ParseFunc, error) {
	parser := paseto.NewParser()
	for _, option := range options {
		option(&parser)
	}
	key, err := paseto.V3SymmetricKeyFromHex(symmetricPubKey)
	if err != nil {
		return nil, nil
	}
	return func(token string) (*paseto.Token, error) {
		return parser.ParseV3Local(key, token, implicit)
	}, nil
}

// NewV3PublicParseFunc will return a function which parse and valid v3 public paseto.
func NewV3PublicParseFunc(asymmetricPubKey string, implicit []byte, options ...ParseOption) (ParseFunc, error) {
	parser := paseto.NewParser()
	for _, option := range options {
		option(&parser)
	}
	key, err := paseto.NewV3AsymmetricPublicKeyFromHex(asymmetricPubKey)
	if err != nil {
		return nil, nil
	}
	return func(token string) (*paseto.Token, error) {
		return parser.ParseV3Public(key, token, implicit)
	}, nil
}

// NewV4LocalParseFunc will return a function which parse and valid v4 local paseto.
func NewV4LocalParseFunc(symmetricPubKey string, implicit []byte, options ...ParseOption) (ParseFunc, error) {
	parser := paseto.NewParser()
	for _, option := range options {
		option(&parser)
	}
	key, err := paseto.V4SymmetricKeyFromHex(symmetricPubKey)
	if err != nil {
		return nil, nil
	}
	return func(token string) (*paseto.Token, error) {
		return parser.ParseV4Local(key, token, implicit)
	}, nil
}

// NewV4PublicParseFunc will return a function which parse and valid v4 public paseto.
func NewV4PublicParseFunc(asymmetricPubKey string, implicit []byte, options ...ParseOption) (ParseFunc, error) {
	parser := paseto.NewParser()
	for _, option := range options {
		option(&parser)
	}
	key, err := paseto.NewV4AsymmetricPublicKeyFromHex(asymmetricPubKey)
	if err != nil {
		return nil, nil
	}
	return func(token string) (*paseto.Token, error) {
		return parser.ParseV4Public(key, token, implicit)
	}, nil
}

// WithAudience requires that the given audience matches the "aud" field of the token.
func WithAudience(audience string) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.ForAudience(audience))
	}
}

// WithIdentifier requires that the given identifier matches the "jti" field of the token.
func WithIdentifier(identifier string) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.IdentifiedBy(identifier))
	}
}

// WithIssuer requires that the given issuer matches the "iss" field of the token.
func WithIssuer(issuer string) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.IssuedBy(issuer))
	}
}

// WithSubject requires that the given subject matches the "sub" field of the token.
func WithSubject(subject string) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.Subject(subject))
	}
}

// WithValidAt requires that the token has not expired according to the given time
// and the "exp" field, and that the given time is both after the token's issued
// at time "iat", and the token's not before time "nbf".
func WithValidAt(time time.Time) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.ValidAt(time))
	}
}

// WithNotBefore requires that the token is allowed to be used according to the time
// when this rule is checked and the "nbf" field of a token. Beware that this
// rule does not validate the token's "iat" or "exp" fields, or even require
// their presence.
func WithNotBefore() ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.NotBeforeNbf())
	}
}

// DefaultParseFunc returns a default ParseFunc(V4 Public).
func DefaultParseFunc() ParseFunc {
	f, _ := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit))
	return f
}
