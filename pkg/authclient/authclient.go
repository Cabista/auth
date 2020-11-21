package authclient

import (
	"fmt"

	"github.com/labstack/echo"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

type AuthClient struct {
	URL    string
	JwkSet *jwk.Set
}

func NewAuthClient(url string) (*AuthClient, error) {
	set, err := jwk.Fetch(url)
	if err != nil {
		return nil, err
	}

	return &AuthClient{
		URL:    url,
		JwkSet: set,
	}, nil
}

func (a *AuthClient) ValidateRequestMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		header := c.Request().Header.Get("Authorization")
		a.ValidateToken(header)
		return next(c)
	}
}

func (a *AuthClient) ValidateToken(token string) (jwt.Token, error) {
	tok, err := jwt.ParseString(token)
	if err != nil {
		return nil, err
	}

	key, found := tok.Get(jwk.KeyIDKey)
	if !found {
		return nil, fmt.Errorf("This JWT does not contain a kid")
	}

	kids := a.JwkSet.LookupKeyID(key.(string))

	var kidErr error

	for _, kid := range kids {
		_, kidErr = jws.VerifyWithJWK([]byte(token), kid)
	}

	if kidErr != nil {
		return nil, fmt.Errorf("Invalid KID")
	}

	err = jwt.Verify(tok)

	if err != nil {
		return nil, err
	}

	return tok, nil
}
