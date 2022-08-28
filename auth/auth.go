package auth

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/topcoder520/gosyproxy/config"
	"github.com/topcoder520/gosyproxy/mylog"
)

const (
	Version = "0.1.0"

	ProxyAuthenticate       = "Proxy-Authenticate"
	ProxyAuthorization      = "Proxy-Authorization"
	ProxyAuthenticationInfo = "Proxy-Authentication-Info"

	AuthKey    = "poiu45ytrkldfs853210dad.,/fdlf;qw2sposd"
	RandSource = 10000 * 10

	PROXY_NAME = "gosyproxy"
	ProxyAgent = "Proxy-Agent"
)

var ErrorProxyAuthorization = errors.New("Proxy-Authorization not found")
var ErrorProxyAuthorizationError = errors.New("Proxy-Authorization incorrect")

func Rand() int {
	s := rand.NewSource(RandSource)
	r := rand.New(s)
	return r.Int()
}

//TODO 把加密算法封装 函数类型

func MD5(s string, rand int) string {
	h := md5.New()
	io.WriteString(h, fmt.Sprintf("%d", rand))
	io.WriteString(h, s)
	io.WriteString(h, AuthKey)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func Sha1(s string, rand int) string {
	h := sha1.New()
	io.WriteString(h, fmt.Sprintf("%d", rand))
	io.WriteString(h, s)
	io.WriteString(h, AuthKey)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func Mix(s string, rand int) string {
	h := md5.New()
	io.WriteString(h, fmt.Sprintf("%d", rand))
	io.WriteString(h, s)
	io.WriteString(h, AuthKey)
	s0 := fmt.Sprintf("%x", h.Sum(nil))
	s1 := sha1.New()
	io.WriteString(s1, s0)
	return fmt.Sprintf("%x", s1.Sum(nil))
}

func AuthRequest(req *http.Request, conn net.Conn, cfg *config.Cfg) error {
	authHeader := req.Header.Get(ProxyAuthorization)
	resp := new(http.Response)
	resp.Header.Add(ProxyAgent, fmt.Sprintf("%s/%s", PROXY_NAME, Version))
	randNumber := Rand()
	if len(authHeader) == 0 {
		resp.StatusCode = http.StatusProxyAuthRequired
		resp.Header.Add(ProxyAuthenticate, fmt.Sprintf("md5,sha1,mix/%d", randNumber))
		resp.ContentLength = 0
		err := resp.Write(conn)
		if err != nil {
			mylog.Println("Write response %s error:%s", ProxyAuthenticate, err)
			return err
		}
		b := bufio.NewReader(conn)
		req2, err := http.ReadRequest(b)
		if err != nil {
			mylog.Println("Read request %s error:%s", ProxyAuthorization, err)
			return err
		}
		authHeader = req2.Header.Get(ProxyAuthorization)
		if len(authHeader) == 0 {
			return ErrorProxyAuthorization
		}
	}
	//md5 md5str rand
	strAuth := strings.Split(authHeader, " ")
	if len(strAuth) != 3 {
		return ErrorProxyAuthorizationError
	}
	var respauth string
	crandNumber, _ := strconv.ParseInt(strAuth[2], 10, 32)
	if strAuth[0] == "md5" {
		s := MD5(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), randNumber)
		if s != strAuth[1] {
			return ErrorProxyAuthorizationError
		}
		respauth = MD5(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), int(crandNumber))
	} else if strAuth[0] == "sha1" {
		s := Sha1(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), randNumber)
		if s != strAuth[1] {
			return ErrorProxyAuthorizationError
		}
		respauth = Sha1(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), int(crandNumber))
	} else {
		s := Mix(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), randNumber)
		if s != strAuth[1] {
			return ErrorProxyAuthorizationError
		}
		respauth = Mix(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), int(crandNumber))
	}
	resp.Header.Del(ProxyAuthenticate)
	resp.Header.Add(ProxyAuthenticationInfo, respauth)
	err := resp.Write(conn)
	if err != nil {
		mylog.Println("Write response %s error:%s", ProxyAuthenticationInfo, err)
		return err
	}
	return nil
}
