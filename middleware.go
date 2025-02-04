package middleware

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type AppMetadata struct {
	Provider  string   `json:"provider"`
	Providers []string `json:"providers"`
	Role      string   `json:"role"`
}

var (
	NO_AUTH_NEEDED = []string{
		"getToken",
		"getOffers",
		"getPointOfSale",
	}
)

func ConfigureCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func CheckAuthMiddleware(next http.Handler, allowedRoles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 	if !shouldCheckToken(r.URL.Path) {
		// 		next.ServeHTTP(w, r)
		// 		return
		// 	}

		// 	tokenString := r.Header.Get("Authorization")

		// 	userAPIURL := fmt.Sprintf("http://localhost:5050/verifyToken?token=%s", tokenString)

		// 	req, err := http.NewRequest("POST", userAPIURL, nil)
		// 	if err != nil {
		// 		http.Error(w, "Error creating request", http.StatusInternalServerError)
		// 		return
		// 	}

		// 	client := &http.Client{}
		// 	resp, err := client.Do(req)
		// 	if err != nil {
		// 		http.Error(w, "Error communicating with user API", http.StatusInternalServerError)
		// 		return
		// 	}
		// 	defer resp.Body.Close()

		// 	if resp.StatusCode != http.StatusOK {
		// 		http.Error(w, "Invalid token", http.StatusUnauthorized)
		// 		return
		// 	}
		// 	next.ServeHTTP(w, r)

		tokenString := r.Header.Get("Access_token")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		err := godotenv.Load(".env")
		if err != nil {
			log.Fatal("Error loading .env file")
		}

		JWTSecret := os.Getenv("JWT_SECRET")
		if JWTSecret == "" {
			http.Error(w, "JWT_SECRET not set in .env file", http.StatusInternalServerError)
			return
		}

		keyFunc := func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
			}
			return JWTSecret, nil
		}

		token, err := jwt.Parse(tokenString, keyFunc, jwt.WithAudience("authenticated"))
		if err != nil {
			log.Fatalf("Error al verificar el token: %v", err)
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if appMetadata, exists := claims["app_metadata"]; exists {
				jsonData, err := json.Marshal(appMetadata)
				if err != nil {
					http.Error(w, "Error marshalling app_metadata", http.StatusInternalServerError)
					return
				}

				var appMeta AppMetadata
				err = json.Unmarshal(jsonData, &appMeta)
				if err != nil {
					log.Println("Error unmarshalling app_metadata:", err)
					http.Error(w, "Error unmarshalling app_metadata", http.StatusInternalServerError)
					return
				}

				for _, role := range allowedRoles {
					if appMeta.Role == role {
						next.ServeHTTP(w, r)
						return
					}
				}

				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			} else {
				http.Error(w, "app_metadata not found in token", http.StatusUnauthorized)
				return
			}
		} else {

			http.Error(w, "Invalid token claims or token is not valid", http.StatusUnauthorized)
			return
		}
	})
}

func shouldCheckToken(route string) bool {
	for _, p := range NO_AUTH_NEEDED {
		if strings.Contains(route, p) {
			return false
		}
	}
	return true
}
