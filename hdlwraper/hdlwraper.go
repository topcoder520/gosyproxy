package hdlwraper

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/topcoder520/gosyproxy/mylog"
	"github.com/topcoder520/gosyproxy/proxy"
)

const (
	Version = "0.1.0"
)

type Hdlwraper struct {
	Proxy *proxy.Proxy
}

func NewHdlwraper() (*Hdlwraper, error) {
	hw := &Hdlwraper{}
	return hw, nil
}

func (hdl *Hdlwraper) SetProxy(proxy *proxy.Proxy) {
	hdl.Proxy = proxy
}

func (hdl *Hdlwraper) handleRequest(req *http.Request) (addr string) {
	if hdl.Proxy != nil {
		if len(strings.TrimSpace(hdl.Proxy.Ip)) == 0 {
			mylog.Fatalln(errors.New("proxy ip is empty"))
		}
		addr = hdl.Proxy.String()
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

func (hdl *Hdlwraper) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	hdl.Forward(resp, req)
}

func (hdl *Hdlwraper) Forward(resp http.ResponseWriter, req *http.Request) {
	connIn, _, err := resp.(http.Hijacker).Hijack()
	if err != nil {
		mylog.Println("Hijack=>", err)
		return
	}
	defer connIn.Close()
	addr := hdl.handleRequest(req)

	mylog.Println("remote address=> ", addr, fmt.Sprintf(" url=> %s %s", req.Method, req.URL.String()))
	connOut, err := net.Dial("tcp", addr)
	if err != nil {
		mylog.Println("Dial out=>", err)
		return
	}
	if req.Method == "CONNECT" {
		if hdl.Proxy != nil {
			//让代理连接 req.Host服务器
			err := connectProxyServer(connOut, req.Host)
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
	err = Transport(connIn, connOut)
	if err != nil {
		mylog.Println("trans error ", err)
	}
}

func MyCopy(src io.Reader, dst io.Writer, ch chan<- error) {
	_, err := io.Copy(dst, src)
	ch <- err
}

//两个io口的连接
func Transport(conn1, conn2 net.Conn) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	go MyCopy(conn1, conn2, wChan)
	go MyCopy(conn2, conn1, rChan)

	select {
	case err = <-wChan:
	case err = <-rChan:
	}

	return
}

func connectProxyServer(conn net.Conn, addr string) error {
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
