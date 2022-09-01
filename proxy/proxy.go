package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/topcoder520/gosyproxy/auth"
	"github.com/topcoder520/gosyproxy/config"
	"github.com/topcoder520/gosyproxy/mylog"
)

type Proxy struct {
	Version    string
	HTTP_PROXY string
	Cfg        *config.Cfg
}

func NewHttpProxy(cfg *config.Cfg) (*Proxy, error) {
	if cfg == nil {
		return nil, config.ErrorMustConfig
	}
	proxy := &Proxy{
		Version:    auth.Version,
		HTTP_PROXY: strings.TrimSpace(cfg.Proxy),
		Cfg:        cfg,
	}
	if len(proxy.HTTP_PROXY) == 0 {
		p := proxy.getEnvAny("HTTP_PROXY", "http_proxy")
		if len(p) > 0 {
			up, err := url.Parse(p)
			if err != nil {
				return nil, fmt.Errorf("proxy address unavailable,err:%s", err)
			}
			if len(up.Scheme) == 0 {
				up.Scheme = "http"
			}
			proxy.Cfg.Proxy = fmt.Sprintf("%s://%s", up.Scheme, up.Host)
			if up.User != nil {
				proxy.Cfg.PxyUserName = up.User.Username()
				proxy.Cfg.PxyPwd, _ = up.User.Password()
			}
			proxy.Cfg.PxyUrl = up
			proxy.HTTP_PROXY = proxy.Cfg.Proxy
		}
	}
	return proxy, nil
}

func (pxy *Proxy) Run() {
	errchan := make(chan int, 1)
	sigchan := make(chan os.Signal, 1)
	server := &http.Server{
		Addr:         pxy.Cfg.Port,
		Handler:      pxy,
		ReadTimeout:  time.Minute * 10,
		WriteTimeout: time.Minute * 10,
	}
	go func() {
		mylog.Println("gosyproxy starting! listen port ", pxy.Cfg.Port)
		if len(pxy.HTTP_PROXY) > 0 {
			mylog.Println("HTTP_PROXY ", pxy.HTTP_PROXY)
		}
		if err := server.ListenAndServe(); err != nil {
			mylog.Println(err)
			errchan <- 1
		}
	}()
	signal.Notify(sigchan, os.Interrupt)
	select {
	case <-errchan:
		mylog.Fatalln("gosyproxy end")
	case <-sigchan:
		mylog.Fatalln("gosyproxy interrupted")
	}
}

func (pxy *Proxy) getEnvAny(names ...string) string {
	for _, n := range names {
		if val := os.Getenv(n); val != "" {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

func (pxy *Proxy) getRemoteAddress(req *http.Request) (addr string) {
	if len(strings.TrimSpace(pxy.HTTP_PROXY)) > 0 {
		addr = pxy.Cfg.PxyUrl.Host
		if req.Method == "CONNECT" {

		} else {
			//http请求
			req.Header.Del("Connection")
			req.Header.Set("Proxy-Connection", "Keep-Alive")
			//设置代理服务器的时候Path要改为携带http的完整路径
			//req.URL.Path = req.URL.String()
		}
	} else {
		addr = req.Host
		if req.Method == "CONNECT" {
			if !strings.Contains(addr, ":") {
				addr = addr + ":443"
			}
		} else {
			if !strings.Contains(addr, ":") {
				addr = addr + ":80"
			}
			req.Header.Del("Proxy-Connection")
			req.Header.Set("Connection", "Keep-Alive")
		}
	}
	return
}

func (pxy *Proxy) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	pxy.forward(resp, req)
}

func (pxy *Proxy) forward(resp http.ResponseWriter, req *http.Request) {
	connIn, _, err := resp.(http.Hijacker).Hijack()
	if err != nil {
		mylog.Println("Hijack=>", err)
		return
	}
	defer connIn.Close()
	//验证请求
	if pxy.Cfg.Auth {
		err = auth.AuthRequest(req, connIn, pxy.Cfg)
		if err != nil {
			mylog.Println("Proxy Authorization fail,err:", err)
			resp := new(http.Response)
			resp.Header = make(http.Header)
			resp.Header.Add(auth.ProxyAgent, fmt.Sprintf("%s/%s", auth.PROXY_NAME, auth.Version))
			resp.StatusCode = http.StatusNonAuthoritativeInfo
			resp.ContentLength = 0
			respByts, _ := httputil.DumpResponse(resp, false)
			connIn.Write(respByts)
			return
		}
	}
	addr := pxy.getRemoteAddress(req)

	mylog.Println("remote address=> ", addr, fmt.Sprintf(" url=> %s %s", req.Method, req.URL.String()))
	connOut, err := net.Dial("tcp", addr)
	if err != nil {
		mylog.Println("Dial out=>", err)
		return
	}
	if len(strings.TrimSpace(pxy.HTTP_PROXY)) > 0 {
		err := pxy.connectProxyServer(connOut, req.Host)
		if err != nil {
			mylog.Println("connectProxyServer=>", err)
			return
		}
	}
	req.Header.Del(auth.ProxyAuthorization)
	req.Header.Del(auth.ProxyAgent)

	if req.Method == "CONNECT" {
		b := []byte("HTTP/1.1 200 Connection Established\r\n" +
			"Proxy-Agent: " + fmt.Sprintf("%s/%s", auth.PROXY_NAME, auth.Version) + "\r\n" +
			"Content-Length: 0" + "\r\n\r\n")
		_, err = connIn.Write(b)
		if err != nil {
			mylog.Println("Write Connect err:", err)
			return
		}
	} else {
		req.Header.Del("Proxy-Connection")
		req.Header.Set("Connection", "Keep-Alive")
		if err = req.Write(connOut); err != nil {
			mylog.Println("send to server err", err)
			return
		}
	}
	err = pxy.transport(connIn, connOut)
	if err != nil {
		mylog.Println("trans error ", err)
	}
}

func (pxy *Proxy) mCopy(src io.Reader, dst io.Writer, ch chan<- error) {
	_, err := io.Copy(dst, src)
	ch <- err
}

//两个io口的连接
func (pxy *Proxy) transport(conn1, conn2 net.Conn) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	go pxy.mCopy(conn1, conn2, wChan)
	go pxy.mCopy(conn2, conn1, rChan)

	select {
	case err = <-wChan:
	case err = <-rChan:
	}

	return
}

func (pxy *Proxy) connectProxyServer(conn net.Conn, addr string) error {
	req := &http.Request{
		Method:     "CONNECT",
		URL:        &url.URL{Host: addr},
		Host:       addr,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	req.Header.Set("Proxy-Connection", "keep-alive")

	select {
	case token := <-auth.AuthPool.Pop():

	}

	req.Header.Add(auth.ProxyAuthorization, "") //todo
	req.Header.Add(auth.ProxyAgent, fmt.Sprintf("%s/%s", auth.PROXY_NAME, auth.Version))

	if err := req.Write(conn); err != nil {
		return fmt.Errorf("write request err:%s", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("read response err:%s", err)
	}
	resp2, err := auth.AuthResponse(resp, req, conn, pxy.Cfg)
	if err != nil {
		return fmt.Errorf("auth response err: %s", err)
	}
	if resp2.StatusCode != http.StatusOK {
		return errors.New("StatusCode != http.StatusOK => " + resp2.Status)
	}
	return nil
}
