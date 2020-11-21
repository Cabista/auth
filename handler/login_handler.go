package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/cabista/auth/data"
	"github.com/cabista/auth/secure"
	"github.com/labstack/echo"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"golang.org/x/crypto/bcrypt"
)

type LoginError struct {
	code    int
	message string
}

type LoginResponse struct {
	Token string
}

type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func PostLogin(c echo.Context) error {
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		return err
	}

	if req.Login == "" || req.Password == "" {
		resp := LoginError{
			code:    1,
			message: "Invalid login or password",
		}
		return c.JSON(http.StatusBadRequest, &resp)
	}

	var user data.User

	data.Database.First(&user, "login = ?", req.Login)

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		fmt.Println(err)
		resp := LoginError{
			code:    1,
			message: "Invalid login or password",
		}
		return c.JSON(http.StatusBadRequest, &resp)
	}

	//user is authenticated
	tok := openid.New()
	tok.Set(jwt.SubjectKey, "https://github.com/cabista")
	tok.Set(jwt.IssuedAtKey, time.Now())
	tok.Set(jwt.NotBeforeKey, time.Now())

	//set expiry for 1 day
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(time.Hour*24)))
	tok.Set(openid.EmailKey, user.Email)
	tok.Set(jwk.KeyIDKey, secure.JWK.KeyID())

	signedJwt, err := jwt.Sign(tok, jwa.RS256, secure.PrivateKey)

	if err != nil {
		fmt.Println(err)
		resp := LoginError{
			code:    1,
			message: "Invalid login or password",
		}
		return c.JSON(http.StatusBadRequest, &resp)
	}

	signedStr := string(signedJwt)
	return c.JSON(http.StatusOK, &LoginResponse{Token: signedStr})
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func PostRegister(c echo.Context) error {
	req := new(RegisterRequest)
	if err := c.Bind(req); err != nil {
		return err
	}

	if req.Password == "" || req.Email == "" {
		resp := LoginError{
			code:    2,
			message: "Fields were not filled out",
		}
		return c.JSON(http.StatusBadRequest, &resp)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	if err != nil {
		resp := LoginError{
			code:    4,
			message: "Internal error",
		}
		return c.JSON(http.StatusInternalServerError, &resp)
	}

	user := data.User{
		Login:        req.Email,
		Email:        req.Email,
		PasswordHash: string(hash),
	}

	data.Database.Create(&user)

	// data.Database.Create(&data.User{
	// 	Login:        req.Email,
	// 	Email:        req.Email,
	// 	PasswordHash: string(hash),
	// })

	return c.JSON(http.StatusOK, &user)
}

func GetJWKs(c echo.Context) error {
	return c.JSON(http.StatusOK, &secure.JWKSet)
}
