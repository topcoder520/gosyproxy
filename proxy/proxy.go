package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/topcoder520/gosyproxy/mylog"
)

const (
	Version = "0.1.0"
)

type Proxy struct {
	Version    string
	HTTP_PROXY string
}

func NewHttpProxy(proxyAddr string) *Proxy {
	proxy := &Proxy{
		Version:    Version,
		HTTP_PROXY: strings.TrimSpace(proxyAddr),
	}
	if len(proxy.HTTP_PROXY) == 0 {
		proxy.HTTP_PROXY = proxy.getEnvAny("HTTP_PROXY", "http_proxy")
	}
	return proxy
}

func (pxy *Proxy) Run(port int) {
	errchan := make(chan int, 1)
	sigchan := make(chan os.Signal, 1)
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      pxy,
		ReadTimeout:  time.Minute * 10,
		WriteTimeout: time.Minute * 10,
	}
	go func() {
		mylog.Println("gosyproxy starting! listen port:", port)
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
		addr = pxy.HTTP_PROXY
		if req.Method == "CONNECT" {

		} else {
			//http请求
			req.Header.Del("Connection")
			req.Header.Set("Proxy-Connection", "Keep-Alive")
			//设置代理服务器的时候Path要改为携带http的完整路径
			req.URL.Path = req.URL.String()
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
	addr := pxy.getRemoteAddress(req)

	mylog.Println("remote address=> ", addr, fmt.Sprintf(" url=> %s %s", req.Method, req.URL.String()))
	connOut, err := net.Dial("tcp", addr)
	if err != nil {
		mylog.Println("Dial out=>", err)
		return
	}
	if req.Method == "CONNECT" {
		if len(strings.TrimSpace(pxy.HTTP_PROXY)) > 0 {
			//让代理连接 req.Host服务器
			err := pxy.connectProxyServer(connOut, req.Host)
			if err != nil {
				mylog.Println("connectProxyServer=>", err)
				return
			}
		}

		b := []byte("HTTP/1.1 200 Connection Established\r\n" +
			"Proxy-Agent: gosyproxy/" + Version + "\r\n" +
			"Content-Length: 0" + "\r\n\r\n")
		_, err = connIn.Write(b)
		if err != nil {
			mylog.Println("Write Connect err:", err)
			return
		}
	} else {
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

	if err := req.Write(conn); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}
