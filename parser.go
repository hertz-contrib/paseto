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

type ParseFunc func(token string) (*paseto.Token, error)

type ParseOption func(ps *paseto.Parser)

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

func WithAudience(audience string) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.ForAudience(audience))
	}
}

func WithIdentifier(identifier string) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.IdentifiedBy(identifier))
	}
}

func WithIssuer(issuer string) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.IssuedBy(issuer))
	}
}

func WithSubject(subject string) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.Subject(subject))
	}
}

func WithValidAt(time time.Time) ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.ValidAt(time))
	}
}

func WithNotBefore() ParseOption {
	return func(ps *paseto.Parser) {
		ps.AddRule(paseto.NotBeforeNbf())
	}
}

func DefaultParseFunc() ParseFunc {
	f, _ := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit))
	return f
}
