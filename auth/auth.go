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
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/topcoder520/gosyproxy/config"
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

var s = rand.NewSource(RandSource)
var r = rand.New(s)

func Rand() int {
	return r.Int()
}

type Encryption interface {
	Encrypt(string, string) string
}

type EncryptFunc func(string, string) string

func (enfc EncryptFunc) Encrypt(s string, rand string) string {
	return enfc(s, rand)
}

func NewEncryption(enc string) Encryption {
	switch strings.ToLower(enc) {
	case "md5":
		return EncryptFunc(func(s string, rand string) string {
			h := md5.New()
			io.WriteString(h, rand)
			io.WriteString(h, s)
			io.WriteString(h, AuthKey)
			return fmt.Sprintf("%x", h.Sum(nil))
		})
	case "sha1":
		return EncryptFunc(func(s string, rand string) string {
			h := sha1.New()
			io.WriteString(h, rand)
			io.WriteString(h, s)
			io.WriteString(h, AuthKey)
			return fmt.Sprintf("%x", h.Sum(nil))
		})
	default:
		return EncryptFunc(func(s string, rand string) string {
			h := md5.New()
			io.WriteString(h, rand)
			io.WriteString(h, s)
			io.WriteString(h, AuthKey)
			s0 := fmt.Sprintf("%x", h.Sum(nil))
			s1 := sha1.New()
			io.WriteString(s1, s0)
			return fmt.Sprintf("%x", s1.Sum(nil))
		})
	}
}

func AuthRequest(req *http.Request, conn net.Conn, cfg *config.Cfg) error {
	authHeader := req.Header.Get(ProxyAuthorization)
	resp := new(http.Response)
	resp.Header = make(http.Header)
	resp.Header.Add(ProxyAgent, fmt.Sprintf("%s/%s", PROXY_NAME, Version))
	randNumber := strconv.Itoa(Rand())
	if len(authHeader) == 0 {
		resp.StatusCode = http.StatusProxyAuthRequired
		resp.Header.Add(ProxyAuthenticate, fmt.Sprintf("md5,sha1,mix/%s", randNumber))
		resp.ContentLength = 0
		respByts, err := httputil.DumpResponse(resp, false)
		if err != nil {
			return err
		}
		_, err = conn.Write(respByts)
		if err != nil {
			return fmt.Errorf("Write response %s error:%s", ProxyAuthenticate, err)
		}
		b := bufio.NewReader(conn)
		req2, err := http.ReadRequest(b)
		if err != nil {
			return fmt.Errorf("Read request %s error:%s", ProxyAuthorization, err)
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
	crandNumber := strAuth[2]
	enc := NewEncryption(strAuth[0])
	s := enc.Encrypt(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), randNumber)
	if s != strAuth[1] {
		return ErrorProxyAuthorizationError
	}
	respauth = enc.Encrypt(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), crandNumber)
	resp.Header.Del(ProxyAuthenticate)
	resp.Header.Add(ProxyAuthenticationInfo, respauth)
	respByts, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return err
	}
	_, err = conn.Write(respByts)
	if err != nil {
		return fmt.Errorf("Write response %s error:%s", ProxyAuthenticationInfo, err)
	}
	return nil
}
