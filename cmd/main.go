package main

import (
	"flag"
	"os"

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
	if logfile {
		mylog.SetLogFile("./log/", "mylog.log")
	} else {
		mylog.SetLog(os.Stdout)
	}
	proxy := proxy.NewHttpProxy(Proxy)
	proxy.Run(Port)
}
