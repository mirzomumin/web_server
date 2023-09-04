package auth

import (
	"github.com/golang-jwt/jwt"
	"github.com/mirzomumin/web_server/internal/domains"
	"github.com/joho/godotenv"
	"os"
)

func GenerateJWT(user *domains.User) (string, error) {
	godotenv.Load(".env")
	token := jwt.NewWithClaims(
	jwt.SigningMethodHS256,
	jwt.MapClaims{
		"user_id": user.Id,
		"login":  user.Login,
	})
	tokenString, err := token.SignedString(
		[]byte(os.Getenv("SECRET_KEY")))
	return tokenString, err
}