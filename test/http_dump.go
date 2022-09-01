package test

import (
	"fmt"
	"net/http"
	"net/http/httputil"
)

func DumpRequest(req *http.Request) {
	b, err := httputil.DumpRequest(req, false)
	if err != nil {
		fmt.Println("DumpRequest=>", err)
		return
	}
	fmt.Println(string(b))
}

func DumpResponse(resp *http.Response) {
	b, err := httputil.DumpResponse(resp, false)
	if err != nil {
		fmt.Println("DumpResponse=>", err)
		return
	}
	fmt.Println(string(b))
}
