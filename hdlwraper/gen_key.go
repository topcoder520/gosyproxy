package hdlwraper

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/topcoder520/gosyproxy/mylog"
)

// PEM证书格式的头类型
const (
	PEM_BLOCK_TYPE_PRIVATE_KEY = "RSA PRIVATE KEY"
	PEM_BLOCK_TYPE_PUBLIC_KEY  = "RSA PRIVATE KEY"
	PEM_BLOCK_TYPE_CERTIFICATE = "CERTIFICATE"
)

//PrivateKey 秘钥封装
type PrivateKey struct {
	rsakey *rsa.PrivateKey
}

//GeneratePK 生成秘钥
func GeneratePK(bits int) (key *PrivateKey, err error) {
	rsakey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{rsakey: rsakey}, nil
}

//LoadPKFromFile 从pem编码文件导入秘钥
func LoadPKFromFile(filename string) (key *PrivateKey, err error) {
	pkBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("unable to read private key file from %s:%s", filename, err)
	}
	block, _ := pem.Decode(pkBytes)
	if block == nil {
		return nil, fmt.Errorf("unable to decode PEM encoded private key data %s", filename)
	}
	rsapk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to decode x509 private key data:%s", err)
	}
	return &PrivateKey{rsakey: rsapk}, nil
}

//pemBlock 秘钥封装成block格式
func (key *PrivateKey) pemBlock() *pem.Block {
	return &pem.Block{
		Type:  PEM_BLOCK_TYPE_PRIVATE_KEY,
		Bytes: x509.MarshalPKCS1PrivateKey(key.rsakey),
	}
}

//PemBlockEncodeToBytes pem编码的秘钥存储切片数组
func (key *PrivateKey) PemBlockEncodeToBytes() []byte {
	return pem.EncodeToMemory(key.pemBlock())
}

func (key *PrivateKey) PemBlockEncodeToFile(filename string) (err error) {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing:%s", filename, err)
	}
	defer f.Close()
	if err := pem.Encode(f, key.pemBlock()); err != nil {
		return fmt.Errorf("unable to PEM encode private key: %s", err)
	}
	return
}

type Certificate struct {
	cert     *x509.Certificate
	derBytes []byte
}

/*******************************************************************************
 * Certificate Functions
 ******************************************************************************/

/*
Certificate() generates a certificate for the Public Key of the given PrivateKey
based on the given template and signed by the given issuer. If issuer is nil,
the generated certificate is self-signed.
*/
func (key *PrivateKey) Certificate(template *x509.Certificate, issuer *Certificate) (*Certificate, error) {
	return key.CertificateForKey(template, issuer, &key.rsakey.PublicKey)
}

/*
CertificateForKey() generates a certificate for the given Public Key based on
the given template and signed by the given issuer.  If issuer is nil, the
generated certificate is self-signed.
*/
func (key *PrivateKey) CertificateForKey(template *x509.Certificate, issuer *Certificate, publicKey interface{}) (*Certificate, error) {
	var issuerCert *x509.Certificate
	if issuer == nil {
		// Note - for self-signed certificates, we include the host's external IP address
		issuerCert = template
	} else {
		issuerCert = issuer.cert
	}
	derBytes, err := x509.CreateCertificate(
		rand.Reader, // secure entropy
		template,    // the template for the new cert
		issuerCert,  // cert that's signing this cert
		publicKey,   // public key
		key.rsakey,  // private key
	)
	if err != nil {
		return nil, err
	}
	return bytesToCert(derBytes)
}

// TLSCertificateFor generates a certificate useful for TLS use based on the
// given parameters.  These certs are usable for key encipherment and digital
// signatures.
//
//     organization: the org name for the cert.
//     name:         used as the common name for the cert.  If name is an IP
//                   address, it is also added as an IP SAN.
//     validUntil:   time at which certificate expires
//     isCA:         whether or not this cert is a CA
//     issuer:       the certificate which is issuing the new cert.  If nil, the
//                   new cert will be a self-signed CA certificate.
//
func (key *PrivateKey) TLSCertificateFor(
	organization string,
	name string,
	validUntil time.Time,
	isCA bool,
	issuer *Certificate) (cert *Certificate, err error) {

	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(int64(time.Now().UnixNano())),
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   name,
		},
		NotBefore: time.Now().AddDate(0, -1, 0),
		NotAfter:  validUntil,

		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	// If name is an ip address, add it as an IP SAN
	ip := net.ParseIP(name)
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	isSelfSigned := issuer == nil
	if isSelfSigned {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	// If it's a CA, add certificate signing
	if isCA {
		template.KeyUsage = template.KeyUsage | x509.KeyUsageCertSign
		template.IsCA = true
	}

	cert, err = key.Certificate(template, issuer)
	return
}

// LoadCertificateFromFile loads a Certificate from a PEM-encoded file
func LoadCertificateFromFile(filename string) (*Certificate, error) {
	certificateData, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("Unable to read certificate file from disk: %s", err)
	}
	return LoadCertificateFromPEMBytes(certificateData)
}

// LoadCertificateFromPEMBytes loads a Certificate from a byte array in PEM
// format
func LoadCertificateFromPEMBytes(pemBytes []byte) (*Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("Unable to decode PEM encoded certificate")
	}
	return bytesToCert(block.Bytes)
}

// LoadCertificateFromX509 loads a Certificate from an x509.Certificate
func LoadCertificateFromX509(cert *x509.Certificate) (*Certificate, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   cert.Raw,
	})
	return LoadCertificateFromPEMBytes(pemBytes)
}

// X509 returns the x509 certificate underlying this Certificate
func (cert *Certificate) X509() *x509.Certificate {
	return cert.cert
}

// PEMEncoded encodes the Certificate in PEM
func (cert *Certificate) PEMEncoded() (pemBytes []byte) {
	return pem.EncodeToMemory(cert.pemBlock())
}

// WriteToFile writes the PEM-encoded Certificate to a file.
func (cert *Certificate) WriteToFile(filename string) (err error) {
	certOut, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("Failed to open %s for writing: %s", filename, err)
	}
	defer func() {
		if err := certOut.Close(); err != nil {
			mylog.Printf("Unable to close file: %v", err)
		}
	}()
	return pem.Encode(certOut, cert.pemBlock())
}

func (cert *Certificate) WriteToTempFile() (name string, err error) {
	// Create a temp file containing the certificate
	tempFile, err := ioutil.TempFile("", "tempCert")
	if err != nil {
		return "", fmt.Errorf("Unable to create temp file: %s", err)
	}
	name = tempFile.Name()
	err = cert.WriteToFile(name)
	if err != nil {
		return "", fmt.Errorf("Unable to save certificate to temp file: %s", err)
	}
	return
}

// WriteToDERFile writes the DER-encoded Certificate to a file.
func (cert *Certificate) WriteToDERFile(filename string) (err error) {
	certOut, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("Failed to open %s for writing: %s", filename, err)
	}
	defer func() {
		if err := certOut.Close(); err != nil {
			mylog.Printf("Unable to close file: %v", err)
		}
	}()
	_, err = certOut.Write(cert.derBytes)
	return err
}

// PoolContainingCert creates a pool containing this cert.
func (cert *Certificate) PoolContainingCert() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert.cert)
	return pool
}

// PoolContainingCerts constructs a CertPool containing all of the given certs
// (PEM encoded).
func PoolContainingCerts(certs ...string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		c, err := LoadCertificateFromPEMBytes([]byte(cert))
		if err != nil {
			return nil, err
		}
		pool.AddCert(c.cert)
	}
	return pool, nil
}

func (cert *Certificate) ExpiresBefore(time time.Time) bool {
	return cert.cert.NotAfter.Before(time)
}

func bytesToCert(derBytes []byte) (*Certificate, error) {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert, derBytes}, nil
}

func (cert *Certificate) pemBlock() *pem.Block {
	return &pem.Block{Type: PEM_BLOCK_TYPE_CERTIFICATE, Bytes: cert.derBytes}
}
