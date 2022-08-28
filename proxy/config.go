package proxy

import (
	"errors"
	"flag"
	"os"

	"github.com/topcoder520/gosyproxy/mylog"
)

var DefaultPort = 8088
var ErrorPrintHelpInfo = errors.New("print help info")
var ErrorMustConfig = errors.New("config of proxy is required")

type Cfg struct {
	Port  int
	Proxy string
	Auth  bool

	Logfile bool
	Help    bool
}

func (cfg *Cfg) ParseCmd() error {
	flag.IntVar(&cfg.Port, "port", DefaultPort, "Listen port")
	flag.StringVar(&cfg.Proxy, "proxy", "", "Specifying a proxy server,eg: 127.0.0.1:8888")
	flag.BoolVar(&cfg.Logfile, "log", false, "Prints logs to the specified file")
	flag.BoolVar(&cfg.Help, "help", false, "Print commond help info")
	flag.BoolVar(&cfg.Auth, "auth", false, "Use Digital signatures")
	flag.Parse()
	if cfg.Help {
		flag.Usage()
		return ErrorPrintHelpInfo
	}
	if cfg.Logfile {
		mylog.SetLogFile("./log/", "gosyproxy.log")
	} else {
		mylog.SetLog(os.Stdout)
	}
	return nil
}
