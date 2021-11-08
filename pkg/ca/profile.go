package ca

import (
	"crypto/rand"
	"crypto/x509"

	"github.com/google/uuid"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type common struct {
	PayloadType        string
	PayloadVersion     int
	PayloadIdentifier  string
	PayloadUUID        string
	PayloadDisplayName string
}

type profile struct {
	common
	PayloadScope   string
	PayloadContent []interface{}
}

type securityRootPayload struct {
	common
	PayloadContent []byte
}

func newSecurityRootPayload(c *x509.Certificate) securityRootPayload {
	return securityRootPayload{
		common: common{
			PayloadType:        "com.apple.security.root",
			PayloadVersion:     1,
			PayloadIdentifier:  "debug-mtls.ca-root-cert",
			PayloadUUID:        uuid.New().String(),
			PayloadDisplayName: "debug-mtls CA root certificate",
		},
		PayloadContent: c.Raw,
	}
}

type securityPkcs12Payload struct {
	common
	AllowAllAppsAccess bool
	KeyIsExtractable   bool
	Password           string
	PayloadContent     []byte
}

func newSecurityPkcs12Payload(c *x509.Certificate, k interface{}) (securityPkcs12Payload, error) {
	pwd := uuid.New().String()
	pc, err := pkcs12.Encode(rand.Reader, k, c, []*x509.Certificate{}, pwd)
	if err != nil {
		return securityPkcs12Payload{}, err
	}
	return securityPkcs12Payload{
		common: common{
			PayloadType:        "com.apple.security.pkcs12",
			PayloadVersion:     1,
			PayloadIdentifier:  "debug-mtls.client-cert",
			PayloadUUID:        uuid.New().String(),
			PayloadDisplayName: "debug-mtls client certificate",
		},
		AllowAllAppsAccess: true,
		KeyIsExtractable:   false,
		Password:           pwd,
		PayloadContent:     pc,
	}, nil
}

func newProfile(caCrt *x509.Certificate, cliCrt *x509.Certificate, cliKey interface{}) (profile, error) {
	p := profile{
		common: common{
			PayloadType:        "Configuration",
			PayloadVersion:     1,
			PayloadIdentifier:  "debug-mtls",
			PayloadUUID:        uuid.New().String(),
			PayloadDisplayName: "debug-mtls certificates",
		},
		PayloadScope:   "System",
		PayloadContent: make([]interface{}, 0),
	}
	p.PayloadContent = append(p.PayloadContent, newSecurityRootPayload(caCrt))
	cliP, err := newSecurityPkcs12Payload(cliCrt, cliKey)
	if err != nil {
		return p, err
	}
	p.PayloadContent = append(p.PayloadContent, cliP)
	return p, nil
}
