package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
)

func getUnverifiedTLSCertificateChain(address, serverName string) ([]*x509.Certificate, error) {
	// Add HTTPS default port if port is not specified
	if _, _, err := net.SplitHostPort(address); err != nil {
		const defaultHttpsPortStr = "443"
		address = net.JoinHostPort(address, defaultHttpsPortStr)
	}

	var certs []*x509.Certificate
	cfg := &tls.Config{
		ServerName: serverName,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			certs = make([]*x509.Certificate, len(rawCerts))
			for i, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				certs[i] = cert
			}
			return nil
		},
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", address, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return certs, nil
}
