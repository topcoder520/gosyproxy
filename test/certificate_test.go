package test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

/*
1、根证书生成，自签
2、leaf证书生成并被根证书签名
*/
func TestGenCertificate(t *testing.T) {

	absFilepath, _ := filepath.Abs("./certfiles/")
	err := os.MkdirAll(absFilepath, 0777)
	if err != nil && !os.IsExist(err) {
		log.Fatalln(err)
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(123456),
		//证书持有者信息
		Issuer: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"xxx股份有限公司 ca"},
			OrganizationalUnit: []string{"ca"},
			Province:           []string{"xxx省"},
			Locality:           []string{"xxxx市"},
			StreetAddress:      []string{"xxxx街道"},
			PostalCode:         []string{"邮编"},
			CommonName:         "192.168.1.56", //域名
		},
		NotBefore:             time.Now(),                   //有效开始时间
		NotAfter:              time.Now().AddDate(10, 0, 0), //有效结束时间
		SubjectKeyId:          []byte{1, 2, 3, 5, 6},
		BasicConstraintsValid: true,
		IsCA:                  true, //是否根证书
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	//生成rsa格式的私钥和公钥
	caSelfSignedPrivateKey, _ := rsa.GenerateKey(rand.Reader, 4096) //私钥
	caSelfSignedPublicKey := &caSelfSignedPrivateKey.PublicKey      //公钥
	//根证书自签 返回der编码的切片
	caSelfSigned, err := x509.CreateCertificate(rand.Reader, ca, ca, caSelfSignedPublicKey, caSelfSignedPrivateKey)
	if err != nil {
		log.Fatalln(err)
	}
	//对证书进行pem编码   der编码二进制 pem编码加密后的文本
	capem := new(bytes.Buffer)
	pem.Encode(capem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caSelfSigned,
	})
	//生成自签根证书文件
	ioutil.WriteFile(filepath.Join(absFilepath, "ca.pem"), capem.Bytes(), 0777)
	// 将私钥转换为 DER 格式
	caSelfSignedPrivateKeyDER := x509.MarshalPKCS1PrivateKey(caSelfSignedPrivateKey)
	cakeypem := new(bytes.Buffer)
	pem.Encode(cakeypem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: caSelfSignedPrivateKeyDER,
	})
	//生成根证书密钥文件
	ioutil.WriteFile(filepath.Join(absFilepath, "ca.key"), cakeypem.Bytes(), 0777)

	// 待签署证书及其私钥公钥
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(78956),
		//证书持有者信息
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"xxx股份有限公司"},
			OrganizationalUnit: []string{""},
			Province:           []string{"xxx省"},
			Locality:           []string{"xxxx市"},
			StreetAddress:      []string{"xxxx街道"},
			PostalCode:         []string{"邮编"},
			CommonName:         "127.0.0.1",
		},
		Issuer: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"xxx股份有限公司 ca"},
			OrganizationalUnit: []string{"ca"},
			Province:           []string{"xxx省"},
			Locality:           []string{"xxxx市"},
			StreetAddress:      []string{"xxxx街道"},
			PostalCode:         []string{"邮编"},
			CommonName:         "192.168.1.56", //域名
		},
		NotBefore:    time.Now(),                   //有效开始时间
		NotAfter:     time.Now().AddDate(10, 0, 0), //有效结束时间
		SubjectKeyId: []byte{1, 2, 3, 5, 6},
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certPrivateKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	certPublicKey := &certPrivateKey.PublicKey
	// 使用自签CA 对 证书签署
	certSigned, err2 := x509.CreateCertificate(rand.Reader, cert, ca, certPublicKey, caSelfSignedPrivateKey)
	if err != nil {
		log.Fatalln("create cert2 failed", err2)
	}
	certpem := new(bytes.Buffer)
	pem.Encode(certpem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certSigned,
	})
	//生成证书文件
	ioutil.WriteFile(filepath.Join(absFilepath, "cert.pem"), certpem.Bytes(), 0777)
	certPrivateKeyDER := x509.MarshalPKCS1PrivateKey(certPrivateKey) // 将私钥转换为 DER 编码格式
	certkeypem := new(bytes.Buffer)
	pem.Encode(certkeypem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: certPrivateKeyDER,
	})
	// 私钥写入文件
	ioutil.WriteFile(filepath.Join(absFilepath, "cert.key"), certkeypem.Bytes(), 0777)

	ca_tr, _ := x509.ParseCertificate(caSelfSigned)
	cert_tr, _ := x509.ParseCertificate(certSigned)
	err = cert_tr.CheckSignatureFrom(ca_tr)
	log.Println("check signature", err)
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
	// fmt.Fprintf(w, "This is an example server.\n")
	// io.WriteString(w, "This is an example server.\n")
}

func TestHttps(t *testing.T) {
	fmt.Println("Starting ListenAndServe")
	http.HandleFunc("/hello", HelloServer)
	err := http.ListenAndServeTLS(":1443", "./certfiles/cert.pem", "./certfiles/cert.key", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

var s = mrand.NewSource(10000)
var r = mrand.New(s)

func TestRand(t *testing.T) {
	fmt.Println(r.Int())
	fmt.Println(r.Int())
	fmt.Println(r.Int())
	fmt.Println(r.Int())
}
