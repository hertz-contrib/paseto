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

package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/hertz-contrib/paseto"
)

func performRequest() {
	time.Sleep(time.Second)
	c, _ := client.NewClient()
	req, resp := protocol.AcquireRequest(), protocol.AcquireResponse()

	req.SetMethod("GET")
	req.SetRequestURI("http://127.0.0.1:8080/paseto/correct-issuer")
	_ = c.Do(context.Background(), req, resp)

	req.SetMethod("POST")
	req.SetRequestURI("http://127.0.0.1:8080/paseto")
	req.SetHeader("Authorization", string(resp.Body()))
	_ = c.Do(context.Background(), req, resp)
	fmt.Printf("Authorization response:%s\n", resp.Body())

	req.SetMethod("GET")
	req.SetRequestURI("http://127.0.0.1:8080/paseto/wrong-issuer")
	_ = c.Do(context.Background(), req, resp)

	req.SetMethod("POST")
	req.SetRequestURI("http://127.0.0.1:8080/paseto")
	req.SetHeader("Authorization", string(resp.Body()))
	_ = c.Do(context.Background(), req, resp)
	fmt.Printf("Authorization response:%s,because issuer is wrong", resp.Body())
}

func main() {
	h := server.New(server.WithHostPorts(":8080"))

	h.GET("/paseto/correct-issuer", func(c context.Context, ctx *app.RequestContext) {
		now := time.Now()
		token, err := paseto.DefaultGenTokenFunc()(&paseto.StandardClaims{
			Issuer:    "CloudWeGo-issuer",
			ExpiredAt: now.Add(time.Hour),
			NotBefore: now,
			IssuedAt:  now,
		}, nil, nil)
		if err != nil {
			hlog.Error("generate token failed")
		}
		ctx.String(http.StatusOK, token)
	})
	h.GET("/paseto/wrong-issuer", func(c context.Context, ctx *app.RequestContext) {
		now := time.Now()
		token, err := paseto.DefaultGenTokenFunc()(&paseto.StandardClaims{
			Issuer:    "CloudWeRun-issuer",
			ExpiredAt: now.Add(time.Hour),
			NotBefore: now,
			IssuedAt:  now,
		}, nil, nil)
		if err != nil {
			hlog.Error("generate token failed")
		}
		ctx.String(http.StatusOK, token)
	})

	parseFunc, _ := paseto.NewV4PublicParseFunc(paseto.DefaultPublicKey, []byte(paseto.DefaultImplicit), paseto.WithIssuer("CloudWeGo-issuer"))
	h.POST("/paseto", paseto.New(paseto.WithParseFunc(parseFunc)), func(c context.Context, ctx *app.RequestContext) {
		ctx.String(http.StatusOK, "token is valid")
	})
	go performRequest()
	h.Spin()
}
