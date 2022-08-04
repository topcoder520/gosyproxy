package proxy

import "fmt"

type Proxy struct {
	Ip   string
	Port uint
}

func (proxy Proxy) String() string {
	if proxy.Port == 0 {
		proxy.Port = 80
	}
	return fmt.Sprintf("%s:%d", proxy.Ip, proxy.Port)
}
