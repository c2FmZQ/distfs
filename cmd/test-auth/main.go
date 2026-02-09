package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	addr := flag.String("addr", ":8080", "Address to listen on")
	flag.Parse()

	// Generate Key
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	// JWKS Handler
	http.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwk := map[string]string{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}
		resp := map[string]interface{}{
			"keys": []interface{}{jwk},
		}
		json.NewEncoder(w).Encode(resp)
	})

	// Mint Token Endpoint
	http.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		if email == "" {
			email = "test@example.com"
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"email": email,
			"iss":   "test-auth-server",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
		})
		token.Header["kid"] = kid
		s, err := token.SignedString(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(s))
	})

	log.Printf("Auth Server listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
