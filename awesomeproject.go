package main

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func generateNonce() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)
}

func calculateHash(username, realm, password, nonce, method, uri string) string {
	ha1 := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", username, realm, password))))
	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s", method, uri))))
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))))
}

func digestAuth(w http.ResponseWriter, r *http.Request) {
	const (
		username = "admin"
		password = "password"
		realm    = "myRealm"
	)

	auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

	if len(auth) != 2 || auth[0] != "Digest" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="%s", nonce="%s"`, realm, generateNonce()))
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	digestParts := digestParts(auth[1])
	requiredResponse := calculateHash(username, realm, password, digestParts["nonce"], r.Method, r.URL.Path)

	if digestParts["response"] != requiredResponse {
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hello, %s!", username)
}

func digestParts(authorization string) map[string]string {
	result := map[string]string{}
	for _, part := range strings.Split(authorization, ",") {
		parts := strings.SplitN(part, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		result[key] = value
	}

	return result
}

func main() {
	http.HandleFunc("/", digestAuth)
	http.ListenAndServe(":8080", nil)
}
