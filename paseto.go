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
	"errors"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

var errWrongTokenPrefix = errors.New("wrong prefix for PASETO token")

func New(opts ...Option) app.HandlerFunc {
	options := NewOptions(opts...)
	extractor, err := NewExtractor(options.KeyLookup)
	if err != nil {
		panic(err)
	}
	return func(ctx context.Context, c *app.RequestContext) {
		// Don't execute middleware if Next returns true
		if options.Next != nil && options.Next(ctx, c) {
			c.Next(ctx)
			return
		}
		tokenStr, err := extractor(c)
		if err != nil {
			_ = c.Error(err)
			options.ErrorHandler(ctx, c)
			return
		}
		if options.TokenPrefix != "" {
			if !strings.HasPrefix(tokenStr, options.TokenPrefix) {
				_ = c.Error(errWrongTokenPrefix)
				options.ErrorHandler(ctx, c)
				return
			}
			tokenStr = strings.TrimPrefix(tokenStr, options.TokenPrefix)
		}
		token, err := options.ParseFunc(tokenStr)
		if err != nil {
			_ = c.Error(err)
			options.ErrorHandler(ctx, c)
			return
		}
		options.SuccessHandler(ctx, c, token)
		c.Next(ctx)
	}
}
