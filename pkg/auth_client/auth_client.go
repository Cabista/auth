package auth_client

import "github.com/lestrrat-go/jwx/jwk"

type AuthClient struct {
	url    string
	jwkSet *jwk.Set
}

func NewAuthClient(url string) (*AuthClient, error) {
	set, err := jwk.Fetch(url)
	if err != nil {
		return nil, err
	}
	return &AuthClient{
		url:    url,
		jwkSet: set,
	}, nil
}
