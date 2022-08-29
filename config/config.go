package config

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/topcoder520/gosyproxy/mylog"
)

var DefaultPort = 8088
var ErrorPrintHelpInfo = errors.New("print help info")
var ErrorMustConfig = errors.New("config of proxy is required")

type Cfg struct {
	Port     string
	Auth     bool
	UserName string
	Pwd      string

	Proxy       string
	PxyUserName string
	PxyPwd      string

	Logfile bool
	Help    bool
}

func (cfg *Cfg) ParseCmd() error {
	var local string
	var proxy string
	flag.BoolVar(&cfg.Logfile, "log", false, "Prints logs to the specified file")
	flag.BoolVar(&cfg.Help, "help", false, "Print commond help info")
	flag.StringVar(&local, "L", "", "local listen port,e.g :8080 or admin:123456@localhost:8080")
	flag.StringVar(&proxy, "P", "", "specifying a proxy,e.g 192.168.1.1:8081 or http://admin:123456@192.168.1.1:8081")
	flag.Parse()

	if len(local) == 0 {
		return fmt.Errorf("no listening port is available")
	}
	reg, err := regexp.Compile("^:\\d$")
	if err != nil {
		return fmt.Errorf("local address can not parse,err:%s", err)
	}
	if reg.MatchString(local) {
		cfg.Port = local
	} else {
		if !strings.HasPrefix(local, "http://") || !strings.HasPrefix(local, "https://") {
			local = "http://" + local
		}
		u, err := url.Parse(local)
		if err != nil {
			return fmt.Errorf("listening port is unavailable,err:%s", err)
		}
		cfg.Port = fmt.Sprintf(":%s", u.Port())
		fmt.Println(u.User.Password())
		if u.User != nil {
			cfg.Auth = true
			cfg.UserName = u.User.Username()
			cfg.Pwd, _ = u.User.Password()
		}
	}

	if len(proxy) > 0 {
		up, err := url.Parse(proxy)
		if err != nil {
			return fmt.Errorf("proxy address unavailable,err:%s", err)
		}
		if len(up.Scheme) == 0 {
			up.Scheme = "http"
		}
		cfg.Proxy = fmt.Sprintf("%s://%s", up.Scheme, up.Host)
		if up.User != nil {
			cfg.PxyUserName = up.User.Username()
			cfg.PxyPwd, _ = up.User.Password()
		}
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
