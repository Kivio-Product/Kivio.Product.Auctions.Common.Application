package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type AppMetadata struct {
	Provider  string   `json:"provider"`
	Providers []string `json:"providers"`
	Role      string   `json:"role"`
}

type Response[T any] struct {
	Data   T        `json:"data,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

type GenerateTokenRequest struct {
	OfferID string `json:"offerId"`
}

type contextKey string

const OfferIDKey contextKey = "offerID"

func ConfigureCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Api_Key, Access_token")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func CheckAuctionsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		tokenString := queryParams.Get("token")

		if tokenString == "" {
			http.Error(w, "Token is missing", http.StatusBadRequest)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
			}
			return []byte("JWT_SECRET"), nil
		})

		if err != nil {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		offerId, ok := claims["offerId"].(string)
		if !ok {
			http.Error(w, "Invalid Token Claims", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), OfferIDKey, offerId)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func CheckAuthMiddleware(next http.Handler, allowedRoles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		err := godotenv.Load(".env")
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		apiKeyHeader := r.Header.Get("Api_Key")
		if apiKeyHeader == "" {
			http.Error(w, "Missing Api key", http.StatusBadRequest)
			return
		}
		if !validateAPIKey(apiKeyHeader) {
			http.Error(w, "Invalid Api Key", http.StatusUnauthorized)
			return
		}

		tokenString := r.Header.Get("Access_token")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		token, err := validateToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
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

func VerifyInternalRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := godotenv.Load(".env")
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		apiKeyHeader := r.Header.Get("Api_Key")
		if apiKeyHeader == "" {
			http.Error(w, "Missing Api key", http.StatusBadRequest)
			return
		}
		if !validateAPIKey(apiKeyHeader) {
			http.Error(w, "Invalid Api Key", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validateAPIKey(apiKeyHeader string) bool {
	apiKey := os.Getenv("API_KEY")
	return apiKey != "" && apiKey == apiKeyHeader
}

func validateToken(tokenString string) (*jwt.Token, error) {
	JWTSecret := os.Getenv("JWT_SECRET")

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(JWTSecret), nil
	}

	token, err := jwt.Parse(tokenString, keyFunc, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	return token, nil
}
