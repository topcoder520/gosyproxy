package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/topcoder520/gosyproxy/hdlwraper"
	"github.com/topcoder520/gosyproxy/mylog"
	"github.com/topcoder520/gosyproxy/proxy"
)

var Port int

var Proxy string

var logfile bool

func init() {
	flag.IntVar(&Port, "p", 8888, "port")
	flag.StringVar(&Proxy, "proxy", "", "proxy")
	flag.BoolVar(&logfile, "log", false, "log file")
	flag.Parse()
}

func main() {
	if len(strings.TrimSpace(Proxy)) == 0 {
		Proxy = os.Getenv("HTTP_PROXY")
	}
	var w io.WriteCloser
	if logfile {
		var err error
		fpath, err := filepath.Abs("./log/")
		if err != nil {
			panic(err)
		}
		err = os.MkdirAll(fpath, 0666)
		if err != nil && !os.IsExist(err) {
			panic(err)
		}
		w, err = os.Create(filepath.Join(fpath, "mylog.log"))
		if err != nil {
			panic(err)
		}
	} else {
		w = os.Stdout
	}
	mylog.SetLog(w)

	mylog.Println("listening server port ", Port)
	handler, err := hdlwraper.NewHdlwraper()
	if err != nil {
		mylog.Fatalln(err)
	}
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
	mylog.Println("Listen And Serve HTTP")
	if err := server.ListenAndServe(); err != nil {
		mylog.Fatalln(err)
	}
}
