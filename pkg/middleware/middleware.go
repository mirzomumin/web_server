package middleware

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"net/http"
	"os"
)

func AuthMiddleware(next http.Handler) http.Handler {
	godotenv.Load(".env")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cookie, err := r.Cookie("SESSTOKEN")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Unauthorized!"}`))
		} else {
			jwtToken := cookie.Value
			token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(os.Getenv("SECRET_KEY")), nil
			})

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				ctx := context.WithValue(r.Context(), "props", claims)
				// Access context values in handlers like this
				// props, _ := r.Context().Value("props").(jwt.MapClaims)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				fmt.Println(err)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error": "Unauthorized"}`))
			}
		}
	})
}

func ContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if contentType == "application/json" || contentType == "" {
			next.ServeHTTP(w, r)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Invalid Content-Type. It should be \"application/json\""}`))
		}
	})
}
