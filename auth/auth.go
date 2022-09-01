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
	"sync"
	"time"

	"github.com/topcoder520/gosyproxy/config"
	"github.com/topcoder520/gosyproxy/test"
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

///////AuthTokenPool////////

var AuthPool *AuthTokenPool
var SAuthPool *ServerAuthPool

func init() {
	AuthPool = &AuthTokenPool{
		tokenPool: make(chan *AuthToken, 10000),
		duration:  10 * time.Second,
	}
	SAuthPool = &ServerAuthPool{
		data:     map[string]*AuthToken{},
		duration: 100 * time.Second,
	}
}

type AuthToken struct {
	Token    string
	DealLine time.Time
}

type AuthTokenPool struct {
	tokenPool chan *AuthToken
	duration  time.Duration
}

func (pool *AuthTokenPool) Push(token string) {
	authToken := new(AuthToken)
	authToken.Token = token
	authToken.DealLine = time.Now().Add(pool.duration)
	pool.tokenPool <- authToken
}

func (pool *AuthTokenPool) TokenPool() chan *AuthToken {
	return pool.tokenPool
}

func (pool *AuthTokenPool) Pop() (token *AuthToken) {
selectToken:
	select {
	case t := <-pool.tokenPool:
		if t.DealLine.Before(time.Now()) {
			goto selectToken
		}
		token = t
	default:
		token = nil
	}
	return
}

/////////////

////////ServerAuthPool/////////

type ServerAuthPool struct {
	data     map[string]*AuthToken
	syn      sync.Mutex
	duration time.Duration
}

func (sap *ServerAuthPool) Add(token string) {
	sap.syn.Lock()
	defer sap.syn.Unlock()
	authToken := new(AuthToken)
	authToken.Token = token
	authToken.DealLine = time.Now().Add(sap.duration)
	sap.data[token] = authToken
	if len(sap.data) >= 2000 {
		for k, _ := range sap.data {
			t := sap.data[k]
			if t.DealLine.Before(time.Now()) {
				delete(sap.data, k)
			}
		}
	}
}

func (sap *ServerAuthPool) IsValid(token string) bool {
	sap.syn.Lock()
	defer sap.syn.Unlock()
	tk, ok := sap.data[token]
	if !ok {
		return false
	}
	delete(sap.data, token)
	return !tk.DealLine.Before(time.Now())
}

//////////////////

func AuthRequest(req *http.Request, conn net.Conn, cfg *config.Cfg) error {
	fmt.Println("==============req=============")
	test.DumpRequest(req)
	authHeader := req.Header.Get(ProxyAuthorization)
	resp := new(http.Response)
	resp.Header = make(http.Header)
	resp.Header.Add(ProxyAgent, fmt.Sprintf("%s/%s", PROXY_NAME, Version))
	randNumber := strconv.Itoa(Rand())
ValidToken:
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
		test.DumpRequest(req2)
		if err != nil {
			return fmt.Errorf("Read request %s error:%s", ProxyAuthorization, err)
		}
		authHeader = req2.Header.Get(ProxyAuthorization)
		if len(authHeader) == 0 {
			return ErrorProxyAuthorization
		}
		//md5 md5str rand
		strAuth := strings.Split(authHeader, " ")
		if len(strAuth) != 3 {
			return fmt.Errorf("strAuth len() %s", ErrorProxyAuthorizationError)
		}

		crandNumber := strAuth[2]
		encType := strAuth[0]
		enc := NewEncryption(encType)
		s := enc.Encrypt(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), randNumber)
		if !EqualNotSpace(s, strAuth[1]) {
			return fmt.Errorf("strAuth EqualNotSpace() %s", ErrorProxyAuthorizationError)
		}
		var respauth string
		respauth = enc.Encrypt(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), crandNumber)
		resp.StatusCode = http.StatusOK
		resp.Header.Del(ProxyAuthenticate)
		//md5 respauth rand
		randNumber = strconv.Itoa(Rand())

		resp.Header.Add(ProxyAuthenticationInfo, fmt.Sprintf("%s %s %s", encType, respauth, randNumber))
		s = enc.Encrypt(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), randNumber)
		SAuthPool.Add(s)
		respByts, err = httputil.DumpResponse(resp, false)
		if err != nil {
			return err
		}
		_, err = conn.Write(respByts)
		if err != nil {
			return fmt.Errorf("Write response %s error:%s", ProxyAuthenticationInfo, err)
		}
		return nil
	} else {
		if !SAuthPool.IsValid(authHeader) {
			authHeader = ""
			goto ValidToken
		}
		//md5 md5str rand
		strAuth := strings.Split(authHeader, " ")
		if len(strAuth) != 3 {
			return fmt.Errorf("strAuth len() %s", ErrorProxyAuthorizationError)
		}
		crandNumber := strAuth[2]
		encType := strAuth[0]
		enc := NewEncryption(encType)
		var respauth string
		respauth = enc.Encrypt(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), crandNumber)
		resp.StatusCode = http.StatusOK
		resp.Header.Del(ProxyAuthenticate)
		//md5 respauth rand
		randNumber = strconv.Itoa(Rand())
		resp.Header.Add(ProxyAuthenticationInfo, fmt.Sprintf("%s %s %s", encType, respauth, randNumber))
		s := enc.Encrypt(fmt.Sprintf("%s:%s", cfg.UserName, cfg.Pwd), randNumber)
		SAuthPool.Add(s)
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
}

func AuthResponse(resp *http.Response, req *http.Request, conn net.Conn, cfg *config.Cfg, sandNumber string) (*http.Response, error) {
	agent := resp.Header.Get(ProxyAgent)
	if !strings.HasPrefix(agent, PROXY_NAME) {
		return resp, nil
	}
	var err error
	if resp.StatusCode == http.StatusProxyAuthRequired {
		pxyAuth := resp.Header.Get(ProxyAuthenticate)
		if len(pxyAuth) == 0 {
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
		req.Header.Set(ProxyAuthorization, fmt.Sprintf("%s %s %s", algorithm, reauth, sandNumber))
		if err := req.Write(conn); err != nil {
			return nil, err
		}
		fmt.Println("=======AuthResponse=========")
		test.DumpRequest(req)
		resp, err = http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return nil, err
		}
	} else if resp.StatusCode != http.StatusOK {
		return resp, nil
	}
	//md5 respauth rand
	pxyAuthInfo := resp.Header.Get(ProxyAuthenticationInfo)
	if len(pxyAuthInfo) == 0 {
		return resp, nil
	}
	authInfoArr := strings.Split(pxyAuthInfo, " ")
	if len(authInfoArr) != 3 {
		return nil, fmt.Errorf("read request %s error", ProxyAuthenticationInfo)
	}
	algorithm := authInfoArr[0]
	enc := NewEncryption(algorithm)
	reauth := enc.Encrypt(fmt.Sprintf("%s:%s", cfg.PxyUserName, cfg.PxyPwd), sandNumber)
	if !EqualNotSpace(reauth, authInfoArr[1]) {
		return nil, fmt.Errorf("proxy server verification failed")
	}
	//预授权-------------------start-------生产
	sandNumberStr := authInfoArr[2]
	reauth = enc.Encrypt(fmt.Sprintf("%s:%s", cfg.PxyUserName, cfg.PxyPwd), sandNumberStr)
	AuthPool.Push(fmt.Sprintf("%s %s", algorithm, reauth))
	//预授权-------------------end-------

	//等待代理返回隧道是否连接成功
	resp = nil
	resp, err = http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
