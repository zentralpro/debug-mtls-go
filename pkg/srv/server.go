package srv

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"zentral.pro/dmtls/pkg/ca"
)

func startServer(ca ca.CA, ip string, port int, root string) error {
	http.Handle("/", makeHandler(root))

	caPool, err := ca.CACertPool()
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	addr := fmt.Sprintf("%s:%d", ip, port)
	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
	}

	return server.ListenAndServeTLS(ca.ServerCertPath(), ca.ServerKeyPath())
}
