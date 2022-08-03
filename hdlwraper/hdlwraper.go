package hdlwraper

import (
	"bufio"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/topcoder520/gosyproxy/mylog"
)

var Version = "0.1.0"

type Hdlwraper struct {
	Proxy *Proxy
}

func NewHdlwraper() *Hdlwraper {
	return &Hdlwraper{}
}

func (hdl *Hdlwraper) SetProxy(proxy *Proxy) {
	hdl.Proxy = proxy
}

func (hdl *Hdlwraper) ServeHTTP2(resp http.ResponseWriter, req *http.Request) {
	b, _ := ioutil.ReadAll(req.Body)
	defer req.Body.Close()
	mylog.Printf("url=>%s://%s", strings.ToLower(req.Proto[0:strings.Index(req.Proto, "/")]), req.Host)
	mylog.Println(req.Proto, req.Host, req.Method)
	mylog.Println("body=>", string(b))
	connIn, _, _ := resp.(http.Hijacker).Hijack()
	defer connIn.Close()
	connOut, _ := net.Dial("tcp", req.Host)
	req.Header.Del("Proxy-Connection")
	req.Header.Set("Connection", "keep-alive")
	err := req.Write(connOut)
	if err != nil {
		mylog.Println("connOut=>", err)
		return
	}
	buf := bufio.NewReader(connOut)
	resp2, err := http.ReadResponse(buf, req)
	if err != nil {
		mylog.Println("resp2=>", err)
		return
	}
	resp2.Write(connIn)
}

func (hdl *Hdlwraper) ServeHTTP(resp http.ResponseWriter, req *http.Request) {

	connIn, _, err := resp.(http.Hijacker).Hijack()
	if err != nil {
		mylog.Println("Hijack=>", err)
		return
	}
	defer connIn.Close()
	var addr string
	if hdl.Proxy != nil {
		if len(strings.TrimSpace(hdl.Proxy.Ip)) == 0 {
			mylog.Fatalln(errors.New("proxy ip is empty"))
		}
		addr = hdl.Proxy.String()
	} else {
		if req.Method == "CONNECT" {
			//addr = fmt.Sprintf("%s://%s", strings.ToLower(req.Proto[0:strings.Index(req.Proto, "/")]), req.Host)
			addr = req.Host
			if !strings.Contains(addr, ":") {
				addr = addr + ":443"
			}
		} else {
			addr = req.Host
			if !strings.Contains(addr, ":") {
				addr = addr + ":80"
			}
		}
	}

	mylog.Println("remote address=> ", addr)
	connOut, err := net.Dial("tcp", addr)
	if err != nil {
		mylog.Println("Dial out=>", err)
		return
	}
	if req.Method == "CONNECT" {
		if hdl.Proxy != nil {
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
		req.Header.Del("Proxy-Connection")
		req.Header.Set("Connection", "Keep-Alive")
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
