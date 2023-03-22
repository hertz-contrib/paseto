# PASETO (This is a community driven project)

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the [many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

This is the PASETO middleware for [Hertz](https://github.com/cloudwego/hertz) framework.

## Usage

**Install**

```sh
go get github.com/hertz-contrib/jwt
```

**Import**

```go
import "github.com/hertz-contrib/paseto"
```

## Example

```go
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
	req.SetRequestURI("http://127.0.0.1:8080/paseto")

	req.SetMethod("GET")
	_ = c.Do(context.Background(), req, resp)
	fmt.Printf("get token: %s\n", resp.Body())

	req.SetMethod("POST")
	req.SetHeader("Authorization", string(resp.Body()))
	_ = c.Do(context.Background(), req, resp)
	fmt.Printf("Authorization response :%s", resp.Body())
}

func main() {
	h := server.New(server.WithHostPorts(":8080"))
	h.GET("/paseto", func(c context.Context, ctx *app.RequestContext) {
		now := time.Now()
		genTokenFunc := paseto.DefaultGenTokenFunc()
		token, err := genTokenFunc(&paseto.StandardClaims{
			Issuer:    "cwg-issuer",
			ExpiredAt: now.Add(time.Hour),
			NotBefore: now,
			IssuedAt:  now,
		}, nil, nil)
		if err != nil {
			hlog.Error("generate token failed")
		}
		ctx.String(http.StatusOK, token)
	})

	h.POST("/paseto", paseto.New(), func(c context.Context, ctx *app.RequestContext) {
		ctx.String(http.StatusOK, "token is valid")
	})

	go performRequest()

	h.Spin()
}

```

## Options

| Option         | Default                                 | Description                                                  |
| -------------- |-----------------------------------------| ------------------------------------------------------------ |
| Next           | `nil`                                   | Next defines a function to skip this middleware when returned true. |
| ErrorHandler   | `output log and response 401`           | ErrorHandler defines a function which is executed when an error occurs. |
| SuccessHandler | `save the claims to app.RequestContext` | SuccessHander defines a function which is executed    when the token is valid. |
| KeyLookup      | `"header:Authorization"`                | KeyLookup is a string in the form of "<source>:<key>" that is used to create an Extractor that extracts the token from the request. |
| TokenPrefix    | `""`                                    | TokenPrefix is a string that holds the prefix for the token lookup. |
| ParseFunc      | `parse V4 Public Token`                 | ParseFunc parse and verify token.                            |