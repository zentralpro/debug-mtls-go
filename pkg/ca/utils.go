package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

// see https://play.golang.org/p/MPSqzlITG7
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func loadRSAKey(keyPath string) (*rsa.PrivateKey, error) {
	privBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read private key: %w", err)
	}
	pemBlock, _ := pem.Decode(privBytes)
	if pemBlock == nil {
		return nil, errors.New("could not decode CA private key")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("wrong PEM block type for private key")
	}
	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

func makeRSAKey(keyPath string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(keyPath); err == nil {
		log.Printf("RSA key %s exists", keyPath)
		return loadRSAKey(keyPath)
	}
	log.Printf("Make RSA key %s", keyPath)
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, err
	}

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	err = pem.Encode(file, &pem.Block{
		Type:  rsaPrivateKeyPEMBlockType,
		Bytes: privBytes,
	})
	if err != nil {
		return key, err
	}
	return key, nil
}

func loadECDSAKey(keyPath string) (*ecdsa.PrivateKey, error) {
	privBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read private key: %w", err)
	}
	pemBlock, _ := pem.Decode(privBytes)
	if pemBlock == nil {
		return nil, errors.New("could not decode private key")
	}
	if pemBlock.Type != ecdsaPrivateKeyPEMBlockType {
		return nil, errors.New("wrong PEM block type for private key")
	}
	return x509.ParseECPrivateKey(pemBlock.Bytes)
}

func makeECDSAKey(keyPath string) (*ecdsa.PrivateKey, error) {
	if _, err := os.Stat(keyPath); err == nil {
		log.Printf("ECDSA key %s exists", keyPath)
		return loadECDSAKey(keyPath)
	}
	log.Printf("Make ECDSA key %s", keyPath)
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(file, &pem.Block{
		Type:  ecdsaPrivateKeyPEMBlockType,
		Bytes: privBytes,
	})
	if err != nil {
		return key, err
	}
	return key, nil

}

type certOp struct {
	path   string
	name   string
	serial int64
	ku     x509.KeyUsage
	eku    []x509.ExtKeyUsage
	key    interface{}
	caCrt  *x509.Certificate
	caKey  interface{}
}

func makeCert(op certOp) (*x509.Certificate, error) {
	if _, err := os.Stat(op.path); err == nil {
		log.Printf("Delete existing certificate %s", op.path)
		if err := os.Remove(op.path); err != nil {
			return nil, err
		}
	}
	log.Printf("Make certificate %s", op.path)
	file, err := os.OpenFile(op.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	sbj := pkix.Name{
		CommonName: op.name,
	}

	var pubBytes []byte
	var pubKey crypto.PublicKey
	if rsaKey, ok := op.key.(*rsa.PrivateKey); ok {
		pubKey = rsaKey.Public()
		if pubBytes, err = asn1.Marshal(rsaKey.PublicKey); err != nil {
			return nil, fmt.Errorf("could not marshal rsa public key: %w", err)
		}
	} else if ecdsaKey, ok := op.key.(*ecdsa.PrivateKey); ok {
		pubKey = ecdsaKey.Public()
		encodedPub, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("could not marshal ecdsa public key: %w", err)
		}
		var spki subjectPublicKeyInfo
		_, err = asn1.Unmarshal(encodedPub, &spki)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal serialized ecdsa public key: %w", err)
		}
		pubBytes = spki.SubjectPublicKey.Bytes
	} else {
		return nil, errors.New("Unsupported private key type")
	}
	hash := sha256.Sum256(pubBytes)
	subjKeyId := hash[:20]

	tmpl := &x509.Certificate{
		Subject:      sbj,
		SerialNumber: big.NewInt(op.serial),

		NotBefore: time.Now().Add(-600).UTC(),
		NotAfter:  time.Now().AddDate(0, 0, 800).UTC(),

		KeyUsage:    op.ku,
		DNSNames:    []string{op.name},
		ExtKeyUsage: op.eku,

		SubjectKeyId: subjKeyId,
	}
	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, op.caCrt, pubKey, op.caKey)
	if err != nil {
		return nil, fmt.Errorf("could not create certificate: %w", err)
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %w", err)
	}

	err = pem.Encode(file, &pem.Block{
		Type:  certificatePEMBlockType,
		Bytes: crtBytes,
	})
	if err != nil {
		return crt, fmt.Errorf("could not save certificate: %w", err)
	}
	return crt, nil
}
