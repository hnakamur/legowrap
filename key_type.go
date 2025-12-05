package legowrap

import (
	"errors"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
)

type KeyType int

const (
	KeyTypeInvalid KeyType = iota
	KeyTypeEC256
	KeyTypeEC384
	KeyTypeRSA2048
	KeyTypeRSA3072
	KeyTypeRSA4096
	KeyTypeRSA8192
)

var errKeyTypeInvalid = errors.New("invalid key type")

func KeyTypeFromString(s string) (KeyType, error) {
	switch strings.ToUpper(s) {
	case "EC256":
		return KeyTypeEC256, nil
	case "EC384":
		return KeyTypeEC384, nil
	case "RSA2048":
		return KeyTypeRSA2048, nil
	case "RSA3072":
		return KeyTypeRSA3072, nil
	case "RSA4096":
		return KeyTypeRSA4096, nil
	case "RSA8192":
		return KeyTypeRSA8192, nil
	default:
		return KeyTypeInvalid, errKeyTypeInvalid
	}
}

func (k KeyType) toLegoKeyType() certcrypto.KeyType {
	switch k {
	case KeyTypeEC256:
		return certcrypto.EC256
	case KeyTypeEC384:
		return certcrypto.EC384
	case KeyTypeRSA2048:
		return certcrypto.RSA2048
	case KeyTypeRSA3072:
		return certcrypto.RSA3072
	case KeyTypeRSA4096:
		return certcrypto.RSA4096
	case KeyTypeRSA8192:
		return certcrypto.RSA8192
	default:
		panic("unreachable")
	}
}
