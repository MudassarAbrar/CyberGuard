// This file intentionally contains security vulnerabilities for testing purposes.
// DO NOT use any of the patterns below in production code.

package main

import (
	"crypto/md5"   // CWE-327: Weak cryptographic hash
	"crypto/sha1"  // CWE-327: Weak cryptographic hash
	"database/sql"
	"fmt"
	"math/rand" // CWE-338: Insecure random
	"net/http"
	"os"
	"os/exec"
	"unsafe" // CWE-119: Unsafe pointer usage
)

// CWE-259: Hardcoded credential
const password = "admin123"
const apiKey = "sk-secret-api-key-12345"

// CWE-89: SQL injection via fmt.Sprintf
func getUser(db *sql.DB, username string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", username)
	db.Query(query)
}

// CWE-78: OS command injection via shell interpreter
func runCommand(userInput string) {
	exec.Command("sh", "-c", userInput)
}

// CWE-295: TLS certificate verification disabled
func insecureClient() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_ = tr
}

// CWE-319: Hardcoded HTTP URL
const apiURL = "http://api.example.com/data"

// CWE-338: Insecure random
func generateToken() int {
	return rand.Intn(1_000_000)
}

// CWE-327: MD5 hash usage
func hashData(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// CWE-327: SHA-1 hash usage
func hashDataSha1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// CWE-22: Path traversal
func readFile(userPath string) ([]byte, error) {
	return os.ReadFile("/uploads/" + userPath)
}

// CWE-400: HTTP server without timeouts
func startServer() {
	http.ListenAndServe(":8080", nil)
}

// CWE-119: Unsafe pointer usage (already flagged by import above)
var _ = unsafe.Pointer(nil)
