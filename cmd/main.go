package main

import (
	"log"
	"net/http"

	"github.com/ssz66666/pac2http"
)

func main() {
	listening := ":8080"
	// svr, _ := pac2http.NewPacProxyHTTPServerWithPath("./OmegaProfile_Auto_Switch.pac")
	svr, err := pac2http.NewPacProxyHTTPServerWithURL("https://raw.githubusercontent.com/petronny/gfwlist2pac/master/gfwlist.pac")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening on %s\n", listening)
	log.Fatal(http.ListenAndServe(listening, svr))
}
