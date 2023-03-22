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
	"errors"
	"fmt"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

var (
	errMissingHeader = errors.New("[PASETO] missing token in header")
	errMissingQuery  = errors.New("[PASETO] missing token in query")
	errMissingParam  = errors.New("[PASETO] missing token in param")
	errMissingForm   = errors.New("[PASETO] missing token in form")
	errMissingCookie = errors.New("[PASETO] missing token in cookie")
)

type Extractor func(c *app.RequestContext) (string, error)

func NewExtractor(keyLookup string) (Extractor, error) {
	selectors := strings.Split(keyLookup, ":")
	if len(selectors) != 2 {
		panic(errors.New("[PASETO] KeyLookup must in the form of <source>:<key>"))
	}
	switch selectors[0] {
	case "header":
		return TokenFromHeader(selectors[1]), nil
	case "form":
		return TokenFromForm(selectors[1]), nil
	case "params":
		return TokenFromParams(selectors[1]), nil
	case "query":
		return TokenFromQuery(selectors[1]), nil
	case "cookie":
		return TokenFromCookie(selectors[1]), nil
	default:
		return nil, fmt.Errorf("corrently not support get token from source:%s", selectors[0])
	}
}

// TokenFromParams returns a function that extracts token from the url param string.
func TokenFromParams(param string) Extractor {
	return func(c *app.RequestContext) (string, error) {
		token := c.Param(param)
		if token == "" {
			return "", errMissingParam
		}
		return token, nil
	}
}

// TokenFromForm returns a function that extracts a token from a multipart-form.
func TokenFromForm(key string) Extractor {
	return func(c *app.RequestContext) (string, error) {
		token := c.FormValue(key)
		if string(token) == "" {
			return "", errMissingForm
		}
		return string(token), nil
	}
}

// TokenFromHeader returns a function that extracts token from the request header.
func TokenFromHeader(key string) Extractor {
	return func(c *app.RequestContext) (string, error) {
		token := c.GetHeader(key)
		if string(token) == "" {
			return "", errMissingHeader
		}
		return string(token), nil
	}
}

// TokenFromQuery returns a function that extracts token from the query string.
func TokenFromQuery(key string) Extractor {
	return func(c *app.RequestContext) (string, error) {
		token := c.Query(key)
		if token == "" {
			return "", errMissingQuery
		}
		return token, nil
	}
}

// TokenFromCookie returns a function that extracts token from the request header.
func TokenFromCookie(key string) Extractor {
	return func(c *app.RequestContext) (string, error) {
		token := c.Cookie(key)
		if string(token) == "" {
			return "", errMissingCookie
		}
		return string(token), nil
	}
}
