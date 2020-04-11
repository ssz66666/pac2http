# Pac2HTTP

Pac2HTTP is a package for exposing proxy auto-config (PAC) files as a simple HTTP proxy, so that applications without PAC support can utilise PAC's flexibility.

## Installation

```
go get github.com/ssz66666/pac2http
```

## Example

```go
package main

import (
	"log"
	"net/http"

	"github.com/ssz66666/pac2http"
)

func main() {
	listening := ":8080"
	svr, err := pac2http.NewPacProxyHTTPServerWithURL(
		"https://raw.githubusercontent.com/petronny/gfwlist2pac/master/gfwlist.pac",
	)
    if err != nil {
        log.Fatal(err)
    }
	log.Printf("Listening on %s\n", listening)
	log.Fatal(http.ListenAndServe(listening, svr))
}
```