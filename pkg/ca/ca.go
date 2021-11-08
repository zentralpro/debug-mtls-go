package ca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"time"

	"github.com/groob/plist"
)

const (
	caCN                        = "debug-mtls"
	rsaKeyBits                  = 2048
	certificatePEMBlockType     = "CERTIFICATE"
	rsaPrivateKeyPEMBlockType   = "RSA PRIVATE KEY"
	ecdsaPrivateKeyPEMBlockType = "EC PRIVATE KEY"
)

const (
	caCertSerial = iota + 1
	srvCertSerial
	cliCertSerial
)

const (
	ecdsaMode = iota
	rsaMode
)

type CA struct {
	root string
	mode int

	caCrt       *x509.Certificate
	caRSAKey    *rsa.PrivateKey
	caECDSAKey  *ecdsa.PrivateKey
	srvCrt      *x509.Certificate
	srvRSAKey   *rsa.PrivateKey
	srvECDSAKey *ecdsa.PrivateKey
	cliCrt      *x509.Certificate
	cliRSAKey   *rsa.PrivateKey
	cliECDSAKey *ecdsa.PrivateKey
}

func LoadCA(root string) CA {
	return CA{root: root}
}

func NewCA(root string, ecdsa bool) CA {
	ca := CA{root: root}
	if ecdsa {
		ca.mode = ecdsaMode
	} else {
		ca.mode = rsaMode
	}
	return ca
}

func (ca *CA) CACertPath() string {
	return path.Join(ca.root, "ca.crt")
}

func (ca *CA) caKeyPath() string {
	return path.Join(ca.root, "ca.key")
}

func (ca *CA) ServerCertPath() string {
	return path.Join(ca.root, "server.crt")
}

func (ca *CA) ServerKeyPath() string {
	return path.Join(ca.root, "server.key")
}

func (ca *CA) clientCertPath() string {
	return path.Join(ca.root, "client.crt")
}

func (ca *CA) clientKeyPath() string {
	return path.Join(ca.root, "client.key")
}

func (ca *CA) loadSrvCrt() error {
	p := ca.ServerCertPath()
	_, err := os.Stat(p)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	pemData, err := ioutil.ReadFile(p)
	if err != nil {
		return fmt.Errorf("could not read server certificate: %w", err)
	}
	pemBlock, _ := pem.Decode(pemData)
	if pemBlock == nil {
		return errors.New("could not decode server certificate")
	}
	if pemBlock.Type != certificatePEMBlockType {
		return errors.New("invalid server certificate")
	}
	ca.srvCrt, err = x509.ParseCertificate(pemBlock.Bytes)
	return err
}

func (ca *CA) ServerName() (string, error) {
	if err := ca.loadSrvCrt(); err != nil {
		return "", err
	}
	if ca.srvCrt == nil {
		return "", errors.New("could not find server certificate")
	}
	if len(ca.srvCrt.DNSNames) == 0 {
		return "", errors.New("could not find server name")
	}
	return ca.srvCrt.DNSNames[0], nil
}

func (ca *CA) CACertPool() (*x509.CertPool, error) {
	p := ca.CACertPath()
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("missing CA certificate: %w", err)
	}
	pemData, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("could not read CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(pemData); !ok {
		return nil, errors.New("could not add CA certificate to cert pool")
	}
	return pool, nil
}

// setup

func (ca *CA) makeCADir() error {
	if _, err := os.Stat(ca.root); err == nil {
		log.Print("CA dir exists")
		return nil
	}
	log.Print("Make CA dir")
	if err := os.MkdirAll(ca.root, 0755); err != nil {
		return err
	}
	return nil
}

func (ca *CA) makeCAKey() error {
	var err error
	if ca.mode == ecdsaMode {
		ca.caECDSAKey, err = makeECDSAKey(ca.caKeyPath())
	} else {
		ca.caRSAKey, err = makeRSAKey(ca.caKeyPath())
	}
	return err
}

func (ca *CA) makeCACert() error {
	p := ca.CACertPath()
	if _, err := os.Stat(p); err == nil {
		log.Print("Delete existing CA certificate")
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	log.Print("Make CA certificate")
	file, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	sbj := pkix.Name{
		CommonName: caCN,
	}

	ku := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	tmpl := &x509.Certificate{
		Subject:      sbj,
		SerialNumber: big.NewInt(caCertSerial),

		NotBefore: time.Now().Add(-600).UTC(),
		NotAfter:  time.Now().AddDate(0, 0, 4000).UTC(),

		KeyUsage: ku,

		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	var crtBytes []byte
	if ca.mode == ecdsaMode {
		crtBytes, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ca.caECDSAKey.PublicKey, ca.caECDSAKey)
	} else {
		crtBytes, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ca.caRSAKey.PublicKey, ca.caRSAKey)
	}
	if err != nil {
		return fmt.Errorf("could not create CA certificate: %w", err)
	}
	ca.caCrt, err = x509.ParseCertificate(crtBytes)
	if err != nil {
		return fmt.Errorf("could not parse new CA certificate: %w", err)
	}

	err = pem.Encode(file, &pem.Block{
		Type:  certificatePEMBlockType,
		Bytes: crtBytes,
	})
	if err != nil {
		return fmt.Errorf("could not save CA certificate: %w", err)
	}
	return nil
}

func (ca *CA) makeServerKey() error {
	var err error
	if ca.mode == ecdsaMode {
		ca.srvECDSAKey, err = makeECDSAKey(ca.ServerKeyPath())
	} else {
		ca.srvRSAKey, err = makeRSAKey(ca.ServerKeyPath())
	}
	return err
}

func (ca *CA) makeServerCert(name string) error {
	o := certOp{
		path:   ca.ServerCertPath(),
		name:   name,
		serial: srvCertSerial,
		ku:     x509.KeyUsageDigitalSignature,
		eku:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		caCrt:  ca.caCrt,
	}
	if ca.mode == ecdsaMode {
		o.key = ca.srvECDSAKey
		o.caKey = ca.caECDSAKey
	} else {
		o.key = ca.srvRSAKey
		o.caKey = ca.caRSAKey
	}
	var err error
	ca.srvCrt, err = makeCert(o)
	return err
}

func (ca *CA) makeClientKey() error {
	var err error
	if ca.mode == ecdsaMode {
		ca.cliECDSAKey, err = makeECDSAKey(ca.clientKeyPath())
	} else {
		ca.cliRSAKey, err = makeRSAKey(ca.clientKeyPath())
	}
	return err
}

func (ca *CA) makeClientCert(name string) error {
	o := certOp{
		path:   ca.clientCertPath(),
		name:   name,
		serial: cliCertSerial,
		ku:     x509.KeyUsageDigitalSignature,
		eku:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		caCrt:  ca.caCrt,
	}
	if ca.mode == ecdsaMode {
		o.key = ca.cliECDSAKey
		o.caKey = ca.caECDSAKey
	} else {
		o.key = ca.cliRSAKey
		o.caKey = ca.caRSAKey
	}
	var err error
	ca.cliCrt, err = makeCert(o)
	return err
}

func (ca *CA) ClientMobileconfigPath() string {
	return path.Join(ca.root, "debug-mtls.mobileconfig")
}

func (ca *CA) exportClientMobileconfig() error {
	p := ca.ClientMobileconfigPath()
	log.Printf("Export client mobileconfig %s", p)

	var profile profile
	var err error
	if ca.mode == ecdsaMode {
		profile, err = newProfile(ca.caCrt, ca.cliCrt, ca.cliECDSAKey)
	} else {
		profile, err = newProfile(ca.caCrt, ca.cliCrt, ca.cliRSAKey)
	}
	if err != nil {
		return fmt.Errorf("could not export client mobileconfig: %w", err)
	}
	data, err := plist.MarshalIndent(profile, "  ")
	if err != nil {
		return fmt.Errorf("could not serialize client mobileconfig: %w", err)
	}
	if err := ioutil.WriteFile(ca.ClientMobileconfigPath(), data, 0644); err != nil {
		return fmt.Errorf("could not write client mobileconfig: %w", err)
	}
	return nil
}

func (ca *CA) Setup(srvName string, cliName string) error {
	log.Print("Start")
	if err := ca.makeCADir(); err != nil {
		return err
	}
	if err := ca.makeCAKey(); err != nil {
		return err
	}
	if err := ca.makeCACert(); err != nil {
		return err
	}
	if err := ca.makeServerKey(); err != nil {
		return err
	}
	if err := ca.makeServerCert(srvName); err != nil {
		return err
	}
	if err := ca.makeClientKey(); err != nil {
		return err
	}
	if err := ca.makeClientCert(cliName); err != nil {
		return err
	}
	return ca.exportClientMobileconfig()
}
