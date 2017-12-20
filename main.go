package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	auth0 "github.com/auth0-community/go-auth0"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

type Response struct {
	Message string `json:"message"`
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Print("Error loading .env file")
	}
	c := cors.DefaultConfig()
	c.AllowAllOrigins = true
	c.AddAllowHeaders("Authorization")

	r := gin.New()
	r.Use(
		gin.Logger(),
		gin.Recovery(),
		cors.New(c),
	)

	// public
	public := r.Group("/api/v1")
	{
		public.GET("/public", func(c *gin.Context) {
			c.JSON(http.StatusOK, Response{
				Message: "Hello from a public endpoint! You don't need to be authenticated to see this.",
			})
		})

	}

	// users
	private := r.Group("/api/v1")
	private.Use(jwtMiddleware())
	{
		private.GET("private", func(c *gin.Context) {
			c.JSON(http.StatusOK, Response{
				Message: "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this.",
			})
		})
	}

	fmt.Println("Listening on http://localhost:3010")
	fmt.Println("AUTH0_DOMAIN:", os.Getenv("AUTH0_DOMAIN"))
	fmt.Println("AUTH0_AUDIENCE:", os.Getenv("AUTH0_AUDIENCE"))
	http.ListenAndServe("0.0.0.0:3010", r)
}

func jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Println("I am here")
		JWKS_URI := os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json"
		client := auth0.NewJWKClient(auth0.JWKClientOptions{URI: JWKS_URI})
		aud := os.Getenv("AUTH0_AUDIENCE")
		audience := []string{aud}

		var AUTH0_API_ISSUER = os.Getenv("AUTH0_DOMAIN") + "/"
		configuration := auth0.NewConfiguration(client, audience, AUTH0_API_ISSUER, jose.RS256)
		validator := auth0.NewValidator(configuration)

		token, err := validator.ValidateRequest(c.Request)

		if err != nil {
			fmt.Println("Token is not valid or missing token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, Response{
				Message: "Missing or invalid token.",
			})

		}
		// Ensure the token has the correct scope
		result := checkScope(c.Request, validator, token)
		if result != true {
			// If the token is valid and we have the right scope, we'll pass through the middleware
			c.AbortWithStatusJSON(http.StatusForbidden, Response{
				Message: "You do not have the read:messages scope.",
			})
		}
		c.Next()

	}
}

func checkScope(r *http.Request, validator *auth0.JWTValidator, token *jwt.JSONWebToken) bool {
	claims := map[string]interface{}{}
	err := validator.Claims(r, token, &claims)

	if err != nil {
		fmt.Println(err)
		return false
	}

	if claims["scope"] != nil && strings.Contains(claims["scope"].(string), "read:messages") {
		return true
	} else {
		return false
	}
}
