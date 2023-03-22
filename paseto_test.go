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
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
)

var testV4PublicToken string

func TestDefaultOptions(t *testing.T) {
	opts := NewOptions()
	assert.DeepEqual(t, opts.KeyLookup, "header:Authorization")
	assert.DeepEqual(t, opts.TokenPrefix, "")
}

func TestCustomOption(t *testing.T) {
	opts := NewOptions(WithKeyLookUp("form:Authorization"), WithTokenPrefix("Bearer "))
	assert.DeepEqual(t, opts.KeyLookup, "form:Authorization")
	assert.DeepEqual(t, opts.TokenPrefix, "Bearer ")
}

func init() {
	genTokenFunc := DefaultGenTokenFunc()
	now := time.Now()
	testV4PublicToken, _ = genTokenFunc(&StandardClaims{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		Jti:       "test-identifier",
		ID:        "test-id",
		IssuedAt:  now,
		ExpiredAt: now.Add(time.Hour),
		NotBefore: now,
	}, nil, nil)
}

func TestDefault(t *testing.T) {
	engine := setupEngine("/paseto", New())
	resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Authorization",
		Value: testV4PublicToken,
	}).Result()
	assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())

	resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Authorization",
		Value: testV4PublicToken + "bad",
	}).Result()
	assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
}

func TestWithKeyLookUp(t *testing.T) {
	cases := []struct {
		name string
		op   func(t *testing.T)
	}{
		{
			name: "get token from params",
			op: func(t *testing.T) {
				engine := setupEngine("/:paseto", New(WithKeyLookUp("params:paseto")))
				resp1 := ut.PerformRequest(engine, "POST", "/"+testV4PublicToken, nil).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/"+testV4PublicToken+"bad", nil).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
			},
		},
		{
			name: "get token from form",
			op: func(t *testing.T) {
				engine := setupEngine("/paseto", New(WithKeyLookUp("form:Authorization")))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", &ut.Body{
					Body: bytes.NewBufferString("Authorization=" + testV4PublicToken),
					Len:  -1,
				}, ut.Header{
					Key:   "Content-Type",
					Value: "application/x-www-form-urlencoded",
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", &ut.Body{
					Body: bytes.NewBufferString("Authorization=" + testV4PublicToken + "bad"),
					Len:  -1,
				}, ut.Header{
					Key:   "Content-Type",
					Value: "application/x-www-form-urlencoded",
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", &ut.Body{
					Body: bytes.NewBufferString("paseto=" + testV4PublicToken),
					Len:  -1,
				}, ut.Header{
					Key:   "Content-Type",
					Value: "application/x-www-form-urlencoded",
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "get token form header",
			op: func(t *testing.T) {
				engine := setupEngine("/paseto", New(WithKeyLookUp("header:PASETO")))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "PASETO",
					Value: testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "PASETO",
					Value: testV4PublicToken + "bad",
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "TOKEN",
					Value: testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "get token from query",
			op: func(t *testing.T) {
				engine := setupEngine("/paseto", New(WithKeyLookUp("query:Authorization")))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto?Authorization="+testV4PublicToken, nil).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto?Authorization="+testV4PublicToken+"bad", nil).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "get token from cookie",
			op: func(t *testing.T) {
				engine := setupEngine("/paseto", New(WithKeyLookUp("cookie:Authorization")))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Cookie",
					Value: "Authorization=" + testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Cookie",
					Value: "Authorization=" + testV4PublicToken + "bad",
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "set wrong keyLookUp",
			op: func(t *testing.T) {
				assert.Panic(t, func() {
					New(WithKeyLookUp("raw:Authorization"))
				})
				assert.Panic(t, func() {
					New(WithKeyLookUp("header"))
				})
			},
		},
	}
	for _, c := range cases {
		t.Helper()
		t.Run(c.name, c.op)
	}
}

func TestWithTokenPrefix(t *testing.T) {
	engine := setupEngine("/paseto", New(WithTokenPrefix("Bearer ")))
	resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Authorization",
		Value: "Bearer " + testV4PublicToken,
	}).Result()
	assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
	resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Authorization",
		Value: testV4PublicToken,
	}).Result()
	assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
}

func TestWithErrorFunc(t *testing.T) {
	customErrFunc := func(c context.Context, ctx *app.RequestContext) {
		ctx.String(http.StatusUnauthorized, "invalid token")
		ctx.Abort()
	}

	engine := server.Default().Engine

	engine.POST("/paseto", New(WithErrorFunc(customErrFunc)), func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Authorization",
		Value: testV4PublicToken,
	}).Result()

	resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Authorization",
		Value: "bad" + testV4PublicToken,
	}).Result()

	assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
	assert.DeepEqual(t, "invalid token", string(resp2.Body()))
}

func TestWithNext(t *testing.T) {
	nextFunc := func(c context.Context, ctx *app.RequestContext) bool {
		if string(ctx.Cookie("skip")) == "true" {
			return true
		} else {
			return false
		}
	}

	engine := setupEngine("/paseto", New(WithNext(nextFunc)))
	resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Authorization",
		Value: testV4PublicToken,
	}).Result()
	assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
	resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Cookie",
		Value: "skip=true",
	}).Result()
	assert.DeepEqual(t, http.StatusOK, resp2.StatusCode())
	resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil).Result()
	assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
}

func TestWithSuccessHandler(t *testing.T) {
	successHandler := func(ctx context.Context, c *app.RequestContext, token *paseto.Token) {
		issuer, _ := token.GetIssuer()
		if issuer == "CloudWeGo" {
			return
		}
		c.String(http.StatusBadRequest, "wrong issuer")
		c.Abort()
	}
	engine := setupEngine("/paseto", New(WithSuccessHandler(successHandler)))

	genTokenFunc := DefaultGenTokenFunc()
	token1, err := genTokenFunc(&StandardClaims{
		Issuer:    "CloudWeGo",
		ExpiredAt: time.Now().Add(time.Hour),
	}, nil, nil)
	assert.Nil(t, err)
	token2, err := genTokenFunc(&StandardClaims{
		Issuer:    "CloudWeRun",
		ExpiredAt: time.Now().Add(time.Hour),
	}, nil, nil)
	assert.Nil(t, err)
	resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Authorization",
		Value: token1,
	}).Result()
	assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
	resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
		Key:   "Authorization",
		Value: token2,
	}).Result()
	assert.DeepEqual(t, "wrong issuer", string(resp2.Body()))
}

func TestAllVersion(t *testing.T) {
	cases := []struct {
		name string
		op   func(t *testing.T)
	}{
		{
			name: "use v4 public",
			op: func(t *testing.T) {
				parseFunc, err := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit))
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))

				genTokenFunc, err := NewV4SignFunc(DefaultPrivateKey, []byte(DefaultImplicit))
				assert.Nil(t, err)
				token, err := genTokenFunc(&StandardClaims{
					Issuer:    "v4-public-issuer",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				resp := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp.StatusCode())
			},
		},
		{
			name: "use v4 local",
			op: func(t *testing.T) {
				parseFunc, err := NewV4LocalParseFunc(DefaultSymmetricKey, []byte(DefaultImplicit))
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))

				genTokenFunc, err := NewV4EncryptFunc(DefaultSymmetricKey, []byte(DefaultImplicit))
				assert.Nil(t, err)
				token, err := genTokenFunc(&StandardClaims{
					Issuer:    "v4-local-issuer",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				resp := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp.StatusCode())
			},
		},
		{
			name: "use v3 public",
			op: func(t *testing.T) {
				parseFunc, err := NewV3PublicParseFunc("02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb", []byte(DefaultImplicit))
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))

				genTokenFunc, err := NewV3SignFunc("20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96", []byte(DefaultImplicit))
				assert.Nil(t, err)
				token, err := genTokenFunc(&StandardClaims{
					Issuer:    "v3-public-issuer",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				resp := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp.StatusCode())
			},
		},
		{
			name: "use v3 local",
			op: func(t *testing.T) {
				parseFunc, err := NewV3LocalParseFunc(DefaultSymmetricKey, []byte(DefaultImplicit))
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))

				genTokenFunc, err := NewV3EncryptFunc(DefaultSymmetricKey, []byte(DefaultImplicit))
				assert.Nil(t, err)
				token, err := genTokenFunc(&StandardClaims{
					Issuer:    "v3-local-issuer",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				resp := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp.StatusCode())
			},
		},
		{
			name: "use v2 public",
			op: func(t *testing.T) {
				parseFunc, err := NewV2PublicParseFunc(DefaultPublicKey)
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))

				genTokenFunc, err := NewV2SignFunc(DefaultPrivateKey)
				assert.Nil(t, err)
				token, err := genTokenFunc(&StandardClaims{
					Issuer:    "v2-public-issuer",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				resp := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp.StatusCode())
			},
		},
		{
			name: "use v2 local",
			op: func(t *testing.T) {
				parseFunc, err := NewV2LocalParseFunc(DefaultSymmetricKey)
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))

				genTokenFunc, err := NewV2EncryptFunc(DefaultSymmetricKey)
				assert.Nil(t, err)
				token, err := genTokenFunc(&StandardClaims{
					Issuer:    "v2-local-issuer",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				resp := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp.StatusCode())
			},
		},
	}
	for _, c := range cases {
		t.Helper()
		t.Run(c.name, c.op)
	}
}

func TestParseOption(t *testing.T) {
	cases := []struct {
		name string
		op   func(t *testing.T)
	}{
		{
			name: "with issuer",
			op: func(t *testing.T) {
				parseFunc, err := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit), WithIssuer("cwg-issuer"))
				assert.Nil(t, err)

				token1, err := DefaultGenTokenFunc()(&StandardClaims{
					Issuer:    "cwg-issuer",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				token2, err := DefaultGenTokenFunc()(&StandardClaims{
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token1,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token2,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "with subject",
			op: func(t *testing.T) {
				parseFunc, err := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit), WithSubject("cwg-subject"))
				assert.Nil(t, err)

				token1, err := DefaultGenTokenFunc()(&StandardClaims{
					Subject:   "cwg-subject",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				token2, err := DefaultGenTokenFunc()(&StandardClaims{
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token1,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token2,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "with audience",
			op: func(t *testing.T) {
				parseFunc, err := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit), WithAudience("cwg-audience"))
				assert.Nil(t, err)

				token1, err := DefaultGenTokenFunc()(&StandardClaims{
					Audience:  "cwg-audience",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				token2, err := DefaultGenTokenFunc()(&StandardClaims{
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token1,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token2,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "with identifier",
			op: func(t *testing.T) {
				parseFunc, err := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit), WithIdentifier("cwg-identifier"))
				assert.Nil(t, err)

				token1, err := DefaultGenTokenFunc()(&StandardClaims{
					Jti:       "cwg-identifier",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				token2, err := DefaultGenTokenFunc()(&StandardClaims{
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token1,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token2,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "with subject",
			op: func(t *testing.T) {
				parseFunc, err := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit), WithSubject("cwg-subject"))
				assert.Nil(t, err)

				token1, err := DefaultGenTokenFunc()(&StandardClaims{
					Subject:   "cwg-subject",
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				token2, err := DefaultGenTokenFunc()(&StandardClaims{
					ExpiredAt: time.Now().Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token1,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: token2,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "with validAt",
			op: func(t *testing.T) {
				parseFunc, err := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit), WithValidAt(time.Now().Add(time.Minute*30)))
				assert.Nil(t, err)

				now := time.Now()
				expiredToken, err := DefaultGenTokenFunc()(&StandardClaims{
					IssuedAt:  now,
					NotBefore: now,
					ExpiredAt: now.Add(time.Minute),
				}, nil, nil)
				assert.Nil(t, err)
				notInEffectToken, err := DefaultGenTokenFunc()(&StandardClaims{
					IssuedAt:  now,
					NotBefore: now.Add(time.Minute * 40),
					ExpiredAt: now.Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: expiredToken,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
				resp3 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: notInEffectToken,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp3.StatusCode())
			},
		},
		{
			name: "with notBefore",
			op: func(t *testing.T) {
				parseFunc, err := NewV4PublicParseFunc(DefaultPublicKey, []byte(DefaultImplicit), WithNotBefore())
				assert.Nil(t, err)

				now := time.Now()
				notInEffectToken, err := DefaultGenTokenFunc()(&StandardClaims{
					IssuedAt:  now,
					NotBefore: now.Add(time.Minute * 40),
					ExpiredAt: now.Add(time.Hour),
				}, nil, nil)
				assert.Nil(t, err)

				engine := setupEngine("/paseto", New(WithParseFunc(parseFunc)))
				resp1 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: testV4PublicToken,
				}).Result()
				assert.DeepEqual(t, http.StatusOK, resp1.StatusCode())
				resp2 := ut.PerformRequest(engine, "POST", "/paseto", nil, ut.Header{
					Key:   "Authorization",
					Value: notInEffectToken,
				}).Result()
				assert.DeepEqual(t, http.StatusUnauthorized, resp2.StatusCode())
			},
		},
	}
	for _, c := range cases {
		t.Helper()
		t.Run(c.name, c.op)
	}
}

func setupEngine(path string, middleware app.HandlerFunc) *route.Engine {
	engine := server.Default().Engine
	engine.POST(path, middleware, func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})
	return engine
}
