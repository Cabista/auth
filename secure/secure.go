package secure

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/lestrrat-go/jwx/jwk"
)

var PrivateKey *rsa.PrivateKey
var KeyID string
var JWK jwk.Key
var JWKSet jwk.Set

func LoadKeys(key string, pass string) error {
	var err error
	PrivateKey, err = LoadRSAPrivate(key, pass)
	if err != nil {
		return err
	}
	JWK, err = LoadJWK(PrivateKey)
	if err != nil {
		return err
	}

	JWKSet = jwk.Set{
		Keys: []jwk.Key{JWK},
	}

	return nil
}

func LoadRSAPrivate(file string, pass string) (*rsa.PrivateKey, error) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pema, _ := pem.Decode(content)
	pemDe, err := x509.DecryptPEMBlock(pema, []byte(pass))
	if err != nil {
		return nil, err
	}
	pk, err := x509.ParsePKCS1PrivateKey(pemDe)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func LoadJWK(key *rsa.PrivateKey) (jwk.Key, error) {
	JWKKey, err := jwk.New(key)
	if err != nil {
		return nil, err
	}

	jwk.AssignKeyID(JWKKey)

	return JWKKey, nil
}
