package auth

import (
	"github.com/golang-jwt/jwt"
	"github.com/mirzomumin/web_server/internal/domains"
)

const SECRET_KEY = "MY_SECRET_KEY"

func GenerateJWT(user *domains.User) (string, error) {
	token := jwt.NewWithClaims(
	jwt.SigningMethodHS256,
	jwt.MapClaims{
		"user_id": user.Id,
		"login":  user.Login,
	})
	tokenString, err := token.SignedString([]byte(SECRET_KEY))
	return tokenString, err
}