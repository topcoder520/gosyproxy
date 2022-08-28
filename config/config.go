package config

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

	UserName string
	Pwd      string

	PxyUserName string
	PxyPwd      string

	Logfile bool
	Help    bool
}

func (cfg *Cfg) ParseCmd() error {
	flag.IntVar(&cfg.Port, "port", DefaultPort, "Listen port")
	flag.StringVar(&cfg.Proxy, "proxy", "", "Specifying a proxy server,e.g. 127.0.0.1:8888")
	flag.BoolVar(&cfg.Logfile, "log", false, "Prints logs to the specified file")
	flag.BoolVar(&cfg.Help, "help", false, "Print commond help info")

	flag.StringVar(&cfg.UserName, "u", "", "set account")
	flag.StringVar(&cfg.Pwd, "p", "", "set password")

	flag.StringVar(&cfg.PxyUserName, "pu", "", "set proxy account")
	flag.StringVar(&cfg.PxyPwd, "pp", "", "set proxy password")

	flag.Parse()

	if len(cfg.UserName) > 0 && len(cfg.Pwd) > 0 {
		cfg.Auth = true
	}

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
