package hdlwraper

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// PEM证书格式的头类型
const (
	PEM_BLOCK_TYPE_PRIVATE_KEY = "RSA PRIVATE KEY"
	PEM_BLOCK_TYPE_PUBLIC_KEY  = "RSA PRIVATE KEY"
	PEM_BLOCK_TYPE_CERTIFICATE = "CERTIFICATE"
)

//秘钥封装
type PrivateKey struct {
	rsakey *rsa.PrivateKey
}

func GeneratePK(bits int) (key *PrivateKey, err error) {
	rsakey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{rsakey: rsakey}, nil
}

func LoadPKFromFile(filename string) (key *PrivateKey, err error) {
	pkBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("Unable to read private key file from %s:%s", filename, err)
	}
	block, _ := pem.Decode(pkBytes)
	if block == nil {
		return nil, fmt.Errorf("Unable to decode PEM encoded private key data %s", filename)
	}
	rsapk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode x509 private key data:%s", err)
	}
	return &PrivateKey{rsakey: rsapk}, nil
}

func (key *PrivateKey) pemBlock() *pem.Block {
	return &pem.Block{
		Type:  PEM_BLOCK_TYPE_PRIVATE_KEY,
		Bytes: x509.MarshalPKCS1PrivateKey(key.rsakey),
	}
}

func (key *PrivateKey) PemBlockEncodeToBytes() []byte {
	return pem.EncodeToMemory(key.pemBlock())
}

func (key *PrivateKey) PemBlockEncodeToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("Failed to open file %s for writing:%s", filename, err)
	}
	pem.Encode(f, key.pemBlock())

}

type Certificate struct {
	cert     *x509.Certificate
	derBytes []byte
}
