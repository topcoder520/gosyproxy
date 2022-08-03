package hdlwraper

import (
	"bufio"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/topcoder520/gosyproxy/mylog"
)

type Hdlwraper struct {
}

func NewHdlwraper() *Hdlwraper {
	return &Hdlwraper{}
}

func (hdl *Hdlwraper) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	b, _ := ioutil.ReadAll(req.Body)
	defer req.Body.Close()
	mylog.Println(req.URL.Scheme, req.Host, req.Method)
	mylog.Println("body=>", string(b))
	connIn, _, _ := resp.(http.Hijacker).Hijack()
	defer connIn.Close()
	connOut, _ := net.Dial("tcp", req.Host)
	req.Header.Set("Connection", "keep-alive")
	err := req.Write(connOut)
	if err != nil {
		mylog.Println("connOut=>", err)
		return
	}
	buf := bufio.NewReader(connOut)
	resp2, err := http.ReadResponse(buf, req)
	if err != nil {
		mylog.Println("resp2=>", err)
		return
	}
	resp2.Write(connIn)
}
