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

type StandardClaims struct {
	Issuer    string
	Subject   string
	Audience  string
	Jti       string
	ID        string
	ExpiredAt time.Time
	NotBefore time.Time
	IssuedAt  time.Time
}

type GenTokenFunc func(stdClaims *StandardClaims, customClaims map[string]interface{}, footer []byte) (token string, err error)

func NewV2EncryptFunc(symmetricKey string) (GenTokenFunc, error) {
	key, err := paseto.V2SymmetricKeyFromHex(symmetricKey)
	if err != nil {
		return nil, err
	}
	return func(stdClaims *StandardClaims, customClaims map[string]interface{}, footer []byte) (token string, err error) {
		if tk, err := newTokenFromClaims(stdClaims, customClaims, footer); err != nil {
			return "", err
		} else {
			return tk.V2Encrypt(key), nil
		}
	}, nil
}

func NewV2SignFunc(asymmetricKey string) (GenTokenFunc, error) {
	key, err := paseto.NewV2AsymmetricSecretKeyFromHex(asymmetricKey)
	if err != nil {
		return nil, err
	}
	return func(stdClaims *StandardClaims, customClaims map[string]interface{}, footer []byte) (string, error) {
		if tk, err := newTokenFromClaims(stdClaims, customClaims, footer); err != nil {
			return "", err
		} else {
			return tk.V2Sign(key), nil
		}
	}, nil
}

func NewV3EncryptFunc(symmetricKey string, implicit []byte) (GenTokenFunc, error) {
	key, err := paseto.V3SymmetricKeyFromHex(symmetricKey)
	if err != nil {
		return nil, err
	}
	return func(stdClaims *StandardClaims, customClaims map[string]interface{}, footer []byte) (token string, err error) {
		if tk, err := newTokenFromClaims(stdClaims, customClaims, footer); err != nil {
			return "", err
		} else {
			return tk.V3Encrypt(key, implicit), nil
		}
	}, nil
}

func NewV3SignFunc(asymmetricKey string, implicit []byte) (GenTokenFunc, error) {
	key, err := paseto.NewV3AsymmetricSecretKeyFromHex(asymmetricKey)
	if err != nil {
		return nil, err
	}
	return func(stdClaims *StandardClaims, customClaims map[string]interface{}, footer []byte) (string, error) {
		if tk, err := newTokenFromClaims(stdClaims, customClaims, footer); err != nil {
			return "", err
		} else {
			return tk.V3Sign(key, implicit), nil
		}
	}, nil
}

func NewV4EncryptFunc(symmetricKey string, implicit []byte) (GenTokenFunc, error) {
	key, err := paseto.V4SymmetricKeyFromHex(symmetricKey)
	if err != nil {
		return nil, err
	}
	return func(stdClaims *StandardClaims, customClaims map[string]interface{}, footer []byte) (token string, err error) {
		if tk, err := newTokenFromClaims(stdClaims, customClaims, footer); err != nil {
			return "", err
		} else {
			return tk.V4Encrypt(key, implicit), nil
		}
	}, nil
}

func NewV4SignFunc(asymmetricKey string, implicit []byte) (GenTokenFunc, error) {
	key, err := paseto.NewV4AsymmetricSecretKeyFromHex(asymmetricKey)
	if err != nil {
		return nil, err
	}
	return func(stdClaims *StandardClaims, customClaims map[string]interface{}, footer []byte) (string, error) {
		if tk, err := newTokenFromClaims(stdClaims, customClaims, footer); err != nil {
			return "", err
		} else {
			return tk.V4Sign(key, implicit), nil
		}
	}, nil
}

func newTokenFromClaims(stdClaims *StandardClaims, customClaims map[string]interface{}, footer []byte) (token *paseto.Token, err error) {
	if token, err = paseto.MakeToken(customClaims, footer); err != nil {
		return nil, err
	}

	if stdClaims == nil {
		return
	}

	if stdClaims.Issuer != "" {
		token.SetIssuer(stdClaims.Issuer)
	}
	if stdClaims.Subject != "" {
		token.SetSubject(stdClaims.Subject)
	}
	if stdClaims.Audience != "" {
		token.SetAudience(stdClaims.Audience)
	}
	if stdClaims.Jti != "" {
		token.SetJti(stdClaims.Jti)
	}
	if stdClaims.ID != "" {
		if err = token.Set("id", stdClaims.ID); err != nil {
			return nil, err
		}
	}

	if !stdClaims.ExpiredAt.Equal(time.Time{}) {
		token.SetExpiration(stdClaims.ExpiredAt)
	}
	if !stdClaims.NotBefore.Equal(time.Time{}) {
		token.SetNotBefore(stdClaims.NotBefore)
	}
	if !stdClaims.IssuedAt.Equal(time.Time{}) {
		token.SetIssuedAt(stdClaims.IssuedAt)
	}
	return
}

func DefaultGenTokenFunc() GenTokenFunc {
	f, _ := NewV4SignFunc(DefaultPrivateKey, []byte(DefaultImplicit))
	return f
}
