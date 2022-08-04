package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/topcoder520/gosyproxy/hdlwraper"
	"github.com/topcoder520/gosyproxy/mylog"
	"github.com/topcoder520/gosyproxy/proxy"
)

var Port int

var Proxy string

func init() {
	flag.IntVar(&Port, "p", 8888, "port")
	flag.StringVar(&Proxy, "proxy", "", "port")
}

func main() {
	flag.Parse()

	mylog.SetLog(os.Stdout)

	mylog.Println("listening server port ", Port)

	handler := hdlwraper.NewHdlwraper()
	if len(strings.TrimSpace(Proxy)) > 0 {
		var ip string
		var p uint64
		if strings.Contains(Proxy, ":") {
			ip = Proxy[:strings.Index(Proxy, ":")]
			pp := Proxy[(strings.Index(Proxy, ":") + 1):]
			p, _ = strconv.ParseUint(pp, 10, 64)
		} else {
			ip = Proxy
		}
		handler.SetProxy(&proxy.Proxy{
			Ip:   ip,
			Port: uint(p),
		})
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", Port),
		Handler:      handler,
		ReadTimeout:  time.Minute * 10,
		WriteTimeout: time.Minute * 10,
	}
	if err := server.ListenAndServe(); err != nil {
		mylog.Fatalln(err)
	}
}
