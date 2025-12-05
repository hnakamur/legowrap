package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/go-acme/lego/v4/certcrypto"
)

const accountKeyType = certcrypto.EC256

func generateAccountPrivateKey() (crypto.PrivateKey, error) {
	return certcrypto.GeneratePrivateKey(accountKeyType)
}

func encodeInPEM(data any) ([]byte, error) {
	pemKey := certcrypto.PEMBlock(data)

	var b bytes.Buffer
	err := pem.Encode(&b, pemKey)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func decodeAccountPrivateKeyPEM(pemBytes []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(pemBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}
