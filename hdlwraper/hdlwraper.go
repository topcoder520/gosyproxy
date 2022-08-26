package hdlwraper

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/topcoder520/gosyproxy/config"
	"github.com/topcoder520/gosyproxy/mylog"
	"github.com/topcoder520/gosyproxy/proxy"
)

const (
	Version   = "0.1.0"
	ONE_DAY   = 24 * time.Hour
	TWO_WEEKS = ONE_DAY * 14
	ONE_MONTH = 1
	ONE_YEAR  = 1
)

type Hdlwraper struct {
	Proxy           *proxy.Proxy
	https           bool
	MyConfig        *config.Cfg
	tlsConfig       *config.TlsConfig
	pk              *PrivateKey
	pkPem           []byte
	issuingCert     *Certificate
	issuingCertPem  []byte
	serverTLSConfig *tls.Config
	dynamicCerts    *Cache
	certMutex       sync.Mutex
}

func NewHdlwraper(config *config.TlsConfig, cfg *config.Cfg) (*Hdlwraper, error) {
	hw := &Hdlwraper{dynamicCerts: NewCache(), tlsConfig: config, serverTLSConfig: config.ServerTLSConfig, MyConfig: cfg}
	err := hw.GenerateCertForClient()
	if err != nil {
		return nil, err
	}
	return hw, nil
}

func (hdl *Hdlwraper) SetProxy(proxy *proxy.Proxy) {
	hdl.Proxy = proxy
}

func copyTlsConfig(template *tls.Config) *tls.Config {
	tlsConfig := &tls.Config{}
	if template != nil {
		*tlsConfig = *template
	}
	return tlsConfig
}

func copyHTTPRequest(template *http.Request) *http.Request {
	req := &http.Request{}
	if template != nil {
		*req = *template
	}
	return req
}

func respBadGateway(resp http.ResponseWriter, msg string) {
	log.Println(msg)
	resp.WriteHeader(502)
	resp.Write([]byte(msg))
}

func (hw *Hdlwraper) GenerateCertForClient() (err error) {
	if hw.tlsConfig.Organization == "" {
		hw.tlsConfig.Organization = "gosyproxy" + Version
	}
	if hw.tlsConfig.CommonName == "" {
		hw.tlsConfig.CommonName = "gosyproxy"
	}
	if hw.pk, err = LoadPKFromFile(hw.tlsConfig.PrivateKeyFile); err != nil {
		hw.pk, err = GeneratePK(2048)
		if err != nil {
			return fmt.Errorf("Unable to generate private key: %s", err)
		}
		hw.pk.PemBlockEncodeToFile(hw.tlsConfig.PrivateKeyFile)
	}
	hw.pkPem = hw.pk.PemBlockEncodeToBytes()
	hw.issuingCert, err = LoadCertificateFromFile(hw.tlsConfig.CertFile)
	if err != nil || hw.issuingCert.ExpiresBefore(time.Now().AddDate(0, ONE_MONTH, 0)) {
		hw.issuingCert, err = hw.pk.TLSCertificateFor(
			hw.tlsConfig.Organization,
			hw.tlsConfig.CommonName,
			time.Now().AddDate(ONE_YEAR, 0, 0),
			true,
			nil)
		if err != nil {
			return fmt.Errorf("Unable to generate self-signed issuing certificate: %s", err)
		}
		hw.issuingCert.WriteToFile(hw.tlsConfig.CertFile)
	}
	hw.issuingCertPem = hw.issuingCert.PEMEncoded()
	return
}

func (hw *Hdlwraper) DumpHTTPAndHTTPs(resp http.ResponseWriter, req *http.Request) {
	mylog.Println("DumpHTTPAndHTTPs")
	req.Header.Del("Proxy-Connection")
	req.Header.Set("Connection", "Keep-Alive")
	var reqDump []byte
	var err error
	ch := make(chan bool)
	// handle connection
	go func() {
		reqDump, err = httputil.DumpRequestOut(req, true)
		ch <- true
	}()
	if err != nil {
		mylog.Println("DumpRequest error ", err)
	}
	connIn, _, err := resp.(http.Hijacker).Hijack()
	if err != nil {
		mylog.Println("hijack error:", err)
	}
	defer connIn.Close()

	var respOut *http.Response
	host := req.Host

	matched, _ := regexp.MatchString(":[0-9]+$", host)

	if !hw.https {
		if !matched {
			host += ":80"
		}

		connOut, err := net.DialTimeout("tcp", host, time.Second*30)
		if err != nil {
			mylog.Println("dial to", host, "error:", err)
			return
		}

		if err = req.Write(connOut); err != nil {
			mylog.Println("send to server error", err)
			return
		}

		respOut, err = http.ReadResponse(bufio.NewReader(connOut), req)
		if err != nil && err != io.EOF {
			mylog.Println("read response error:", err)
		}

	} else {
		if !matched {
			host += ":443"
		}

		connOut, err := tls.Dial("tcp", host, hw.tlsConfig.ServerTLSConfig)
		if err != nil {

		}
		if err = req.Write(connOut); err != nil {
			mylog.Println("tls dial to", host, "error:", err)
			return
		}
		if err = req.Write(connOut); err != nil {
			mylog.Println("send to server error", err)
			return
		}

		respOut, err = http.ReadResponse(bufio.NewReader(connOut), req)
		if err != nil && err != io.EOF {
			mylog.Println("read response error:", err)
		}

	}

	if respOut == nil {
		log.Println("respOut is nil")
		return
	}

	respDump, err := httputil.DumpResponse(respOut, true)
	if err != nil {
		mylog.Println("respDump error:", err)
	}

	_, err = connIn.Write(respDump)
	if err != nil {
		mylog.Println("connIn write error:", err)
	}

	if hw.MyConfig.Monitor {
		<-ch
		go httpDump(reqDump, respOut)
	} else {
		<-ch
	}
}
func (hw *Hdlwraper) FakeCertForName(name string) (cert *tls.Certificate, err error) {
	kpCandidateIf, found := hw.dynamicCerts.Get(name)
	if found {
		return kpCandidateIf.(*tls.Certificate), nil
	}

	hw.certMutex.Lock()
	defer hw.certMutex.Unlock()
	kpCandidateIf, found = hw.dynamicCerts.Get(name)
	if found {
		return kpCandidateIf.(*tls.Certificate), nil
	}

	//create certificate
	certTTL := TWO_WEEKS
	generatedCert, err := hw.pk.TLSCertificateFor(
		hw.tlsConfig.Organization,
		name,
		time.Now().Add(certTTL),
		false,
		hw.issuingCert)
	if err != nil {
		return nil, fmt.Errorf("Unable to issue certificate: %s", err)
	}
	keyPair, err := tls.X509KeyPair(generatedCert.PEMEncoded(), hw.pkPem)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse keypair for tls: %s", err)
	}

	cacheTTL := certTTL - ONE_DAY
	hw.dynamicCerts.Set(name, &keyPair, cacheTTL)
	return &keyPair, nil
}

func (hw *Hdlwraper) InterceptHTTPs(resp http.ResponseWriter, req *http.Request) {
	mylog.Println("InterceptHTTPs")
	addr := req.Host
	host := strings.Split(addr, ":")[0]

	cert, err := hw.FakeCertForName(host)
	if err != nil {
		msg := fmt.Sprintf("Could not get mitm cert for name: %s\nerror: %s", host, err)
		respBadGateway(resp, msg)
		return
	}

	// handle connection
	connIn, _, err := resp.(http.Hijacker).Hijack()
	if err != nil {
		msg := fmt.Sprintf("Unable to access underlying connection from client: %s", err)
		respBadGateway(resp, msg)
		return
	}
	tlsConfig := copyTlsConfig(hw.tlsConfig.ServerTLSConfig)
	tlsConfig.Certificates = []tls.Certificate{*cert}
	tlsConnIn := tls.Server(connIn, tlsConfig)
	listener := &Hdllistener{tlsConnIn}
	handler := http.HandlerFunc(func(resp2 http.ResponseWriter, req2 *http.Request) {
		req2.URL.Scheme = "https"
		req2.URL.Host = req2.Host
		hw.DumpHTTPAndHTTPs(resp2, req2)

	})

	go func() {
		err = http.Serve(listener, handler)
		if err != nil && err != io.EOF {
			mylog.Printf("Error serving mitm'ed connection: %s", err)
		}
	}()

	connIn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
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
	// if hdl.Proxy != nil {
	// 	hdl.Forward(resp, req)
	// } else {
	// 	if req.Method == "CONNECT" {
	// 		hdl.https = true
	// 		hdl.InterceptHTTPs(resp, req)
	// 	} else {
	// 		hdl.https = false
	// 		hdl.DumpHTTPAndHTTPs(resp, req)
	// 	}
	// }
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
