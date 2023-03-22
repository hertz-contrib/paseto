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
	"context"
	"net/http"

	"aidanwoods.dev/go-paseto"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
)

const (
	DefaultContextKey   = "paseto"
	DefaultSymmetricKey = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
	DefaultPublicKey    = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
	DefaultPrivateKey   = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
	DefaultImplicit     = "paseto-implicit"
)

// Option is the only struct that can be used to set Options.
type Option struct {
	F func(o *Options)
}

type NextHandler func(ctx context.Context, c *app.RequestContext) bool

type SuccessHandler func(ctx context.Context, c *app.RequestContext, token *paseto.Token)

// Options defines the config for middleware.
type Options struct {
	// Next defines a function to skip middleware.
	// Optional.Default: nil
	Next NextHandler

	// ErrorHandler defines a function which is executed when an error occurs.
	// It may be used to define a custom PASETO error.
	// Optional. Default: OutPut log and response 401.
	ErrorHandler app.HandlerFunc

	// SuccessHandler handle the Parsed token.
	// Optional.Default: Save the claims to app.RequestContext.
	SuccessHandler SuccessHandler

	// KeyLookup is a string in the form of "<source>:<key>" that is used
	// to create an Extractor that extracts the token from the request.
	// Optional. Default: "header:Authorization"
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "param:<name>"
	// - "form:<name>"
	// - "cookie:<name>"
	KeyLookup string

	// TokenPrefix is a string that holds the prefix for the token lookup.
	// Optional. Default value ""
	// Recommended value: "Bearer "
	TokenPrefix string

	// ParseFunc parse and verify token.
	ParseFunc ParseFunc
}

func (o *Options) Apply(opts []Option) {
	for _, op := range opts {
		op.F(o)
	}
}

// DefaultOptions is the default options.
var DefaultOptions = Options{
	Next: nil,
	ErrorHandler: func(ctx context.Context, c *app.RequestContext) {
		hlog.Error("PASTO: ", c.Errors.Last())
		c.String(http.StatusUnauthorized, "authorization failed")
		c.Abort()
	},
	SuccessHandler: func(ctx context.Context, c *app.RequestContext, token *paseto.Token) {
		c.Set(DefaultContextKey, *token)
	},
	KeyLookup: "header:Authorization",
	ParseFunc: DefaultParseFunc(),
}

func NewOptions(opts ...Option) *Options {
	options := DefaultOptions
	options.Apply(opts)
	return &options
}

// WithSuccessHandler sets the logic to handle the Parsed token.
func WithSuccessHandler(f SuccessHandler) Option {
	return Option{
		F: func(o *Options) {
			o.SuccessHandler = f
		},
	}
}

// WithParseFunc sets the ParseFunc.
func WithParseFunc(f ParseFunc) Option {
	return Option{
		F: func(o *Options) {
			o.ParseFunc = f
		},
	}
}

// WithKeyLookUp sets a string in the form of "<source>:<key>" that is used
// to create an Extractor that extracts the token from the request.
func WithKeyLookUp(lookup string) Option {
	return Option{
		F: func(o *Options) {
			o.KeyLookup = lookup
		},
	}
}

// WithTokenPrefix sets the tokenPrefix.
func WithTokenPrefix(tokenPrefix string) Option {
	return Option{
		F: func(o *Options) {
			o.TokenPrefix = tokenPrefix
		},
	}
}

// WithErrorFunc sets ErrorFunc.
func WithErrorFunc(f app.HandlerFunc) Option {
	return Option{
		F: func(o *Options) {
			o.ErrorHandler = f
		},
	}
}

// WithNext sets a function to judge whether to skip this middleware.
func WithNext(f NextHandler) Option {
	return Option{
		F: func(o *Options) {
			o.Next = f
		},
	}
}
