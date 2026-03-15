package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type deviceFlow struct {
	UserCode   string
	DeviceCode string
	Email      string
	Authorized bool
	ExpiresAt  time.Time
}

var (
	flows   = make(map[string]*deviceFlow) // DeviceCode -> Flow
	flowsMu sync.Mutex
)

func main() {
	addr := flag.String("addr", ":8080", "Address to listen on")
	base := flag.String("baseURL", "", "Base URL for OIDC endpoints (e.g. https://web-test-server/auth)")
	flag.Parse()

	// Generate Key
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	mux := http.NewServeMux()

	getURL := func(r *http.Request) string {
		if *base != "" {
			return *base
		}
		host := r.Host
		if host == "" {
			host = "localhost:8080"
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		return scheme + "://" + host
	}

	// JWKS Handler
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Mint Token Endpoint (Direct)
	mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
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

	// Device Authorization Endpoint
	mux.HandleFunc("/device_auth", func(w http.ResponseWriter, r *http.Request) {
		deviceCode := fmt.Sprintf("dc-%d", time.Now().UnixNano())
		userCode := fmt.Sprintf("%04d-%04d", time.Now().Unix()%10000, (time.Now().UnixNano()/100)%10000)

		flowsMu.Lock()
		flows[deviceCode] = &deviceFlow{
			UserCode:   userCode,
			DeviceCode: deviceCode,
			ExpiresAt:  time.Now().Add(5 * time.Minute),
		}
		flowsMu.Unlock()

		baseURL := getURL(r)

		resp := map[string]interface{}{
			"device_code":               deviceCode,
			"user_code":                 userCode,
			"verification_uri":          baseURL + "/auth",
			"verification_uri_complete": baseURL + "/auth?user_code=" + userCode,
			"expires_in":                300,
			"interval":                  1,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Token Endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		deviceCode := r.Form.Get("device_code")

		flowsMu.Lock()
		flow, ok := flows[deviceCode]
		flowsMu.Unlock()

		if !ok || time.Now().After(flow.ExpiresAt) {
			http.Error(w, `{"error":"expired_token"}`, http.StatusBadRequest)
			return
		}

		if !flow.Authorized {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}

		// Artificial delay to ensure UI tests can see the "waiting" state
		time.Sleep(2 * time.Second)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"email": flow.Email,
			"iss":   "test-auth-server",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
		})
		token.Header["kid"] = kid
		s, err := token.SignedString(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := map[string]interface{}{
			"access_token": s,
			"id_token":     s,
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Manual Authorization Endpoint (for Playwright)
	mux.HandleFunc("/authorize_code", func(w http.ResponseWriter, r *http.Request) {
		userCode := r.URL.Query().Get("user_code")
		email := r.URL.Query().Get("email")
		if email == "" {
			email = "test@example.com"
		}

		found := false
		flowsMu.Lock()
		for _, f := range flows {
			if f.UserCode == userCode {
				f.Authorized = true
				f.Email = email
				found = true
				break
			}
		}
		flowsMu.Unlock()

		if !found {
			http.Error(w, "User code not found", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, "Authorized %s", email)
	})

	// Discovery Handler
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		baseURL := getURL(r)
		resp := map[string]string{
			"issuer":                        "test-auth-server",
			"jwks_uri":                      baseURL + "/jwks.json",
			"authorization_endpoint":        baseURL + "/auth",
			"device_authorization_endpoint": baseURL + "/device_auth",
			"token_endpoint":                baseURL + "/token",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Wrap mux to handle both root and /auth/ prefix
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Strip /auth prefix if present
		if strings.HasPrefix(r.URL.Path, "/auth/") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/auth")
		}
		mux.ServeHTTP(w, r)
	})

	log.Printf("Auth Server listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, handler))
}
