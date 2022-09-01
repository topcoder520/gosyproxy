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
	"time"

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

func EqualNotSpace(s1 string, s2 string) bool {
	return strings.TrimSpace(s1) == strings.TrimSpace(s2)
}

///////////////

var AuthPool *AuthTokenPool

func init() {
	AuthPool = &AuthTokenPool{
		tokenPool: make(chan AuthToken, 10000),
		duration:  5 * time.Second,
	}
}

type AuthToken struct {
	Token    string
	DealLine time.Time
}

type AuthTokenPool struct {
	tokenPool chan AuthToken
	duration  time.Duration
}

func (pool *AuthTokenPool) Push(token string) {
	authToken := AuthToken{}
	authToken.Token = token
	authToken.DealLine = time.Now().Add(pool.duration)
	pool.tokenPool <- authToken
}

func (pool *AuthTokenPool) Pop() *AuthToken {
	select {
	case <-auth.AuthPool.Pop():

	}
	for authToken := range pool.tokenPool {
		if authToken.DealLine.Before(time.Now()) {
			continue
		}
		return &authToken
	}
	return nil
}

/////////////

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
	if !EqualNotSpace(s, strAuth[1]) {
		return ErrorProxyAuthorizationError
	}
	respauth = enc.Encrypt(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), crandNumber)
	resp.StatusCode = http.StatusOK
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

func AuthResponse(resp *http.Response, req *http.Request, conn net.Conn, cfg *config.Cfg) (*http.Response, error) {
	agent := resp.Header.Get(ProxyAgent)
	if resp.StatusCode != http.StatusProxyAuthRequired {
		return resp, nil
	}
	pxyAuth := resp.Header.Get(ProxyAuthenticate)
	if len(pxyAuth) == 0 {
		return resp, nil
	}
	if !strings.HasPrefix(agent, PROXY_NAME) {
		return resp, nil
	}
	//md5,sha1,mix/rand
	strArr := strings.Split(pxyAuth, "/")
	if len(strArr) != 2 {
		return nil, errors.New(fmt.Sprintf("Read request %s error", ProxyAuthenticate))
	}
	algorithms := strings.Split(strArr[0], ",")
	if len(algorithms) == 0 {
		return nil, errors.New(fmt.Sprintf("Read request %s error", ProxyAuthenticate))
	}
	var reauth string
	srandNumber := strArr[1]
	rand.Seed(time.Now().Unix())
	n := rand.Intn(len(algorithms))
	algorithm := algorithms[n] //随机选算法
	enc := NewEncryption(algorithm)
	reauth = enc.Encrypt(fmt.Sprintf("%s:%s", cfg.PxyUserName, cfg.PxyPwd), srandNumber)
	//md5 md5str rand
	sandNumber := Rand()
	req.Header.Set(ProxyAuthorization, fmt.Sprintf("%s %s %s", algorithm, reauth, strconv.Itoa(sandNumber)))
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	//very server
	resp2, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	pxyAuthInfo := resp2.Header.Get(ProxyAuthenticationInfo)
	if len(pxyAuthInfo) == 0 {
		return nil, fmt.Errorf("read request %s error:%s", ProxyAuthenticationInfo, err)
	}
	reauth = enc.Encrypt(fmt.Sprintf("%s:%s", cfg.PxyUserName, cfg.PxyPwd), strconv.Itoa(sandNumber))
	if !EqualNotSpace(reauth, pxyAuthInfo) {
		return nil, fmt.Errorf("proxy server verification failed")
	}
	//等待代理返回隧道是否连接成功
	resp2, err = http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	return resp2, nil
}
