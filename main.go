package main

import (
	"github.com/cabista/auth/data"
	"github.com/cabista/auth/handler"
	"github.com/cabista/auth/secure"
	"github.com/labstack/echo"
)

func main() {
	// pk, err := rsa.GenerateKey(rand.Reader, 2048)
	// if err != nil {
	// 	panic(err)
	// }

	err := secure.LoadKeys("./private.pem", "private")
	if err != nil {
		panic(err)
	}
	err = data.Initialize("host=postgres user=admin password=adminpass DB.name=auth port=5432 sslmode=disable")
	if err != nil {
		panic(err)
	}
	e := echo.New()
	e.POST("/login", handler.PostLogin)
	e.POST("/register", handler.PostRegister)
	e.GET("/jwks", handler.GetJWKs)
	e.Logger.Fatal(e.Start(":80"))
}
