package main

import (
	"github.com/topcoder520/gosyproxy/mylog"
	"github.com/topcoder520/gosyproxy/proxy"
)

func main() {
	cfg := new(proxy.Cfg)
	err := cfg.ParseCmd()
	if err != nil {
		return
	}
	pxy, err := proxy.NewHttpProxy(cfg)
	if err != nil {
		mylog.Fatalln(err)
	}
	pxy.Run()
}
