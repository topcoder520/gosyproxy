package hdlwraper

import (
	"io/ioutil"
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
	mylog.Println(req.Host)
	mylog.Println(string(b))
}
