package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credentials represents the AWS credential_process output format.
type Credentials struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey  string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

func cacheKey(accountID, roleName, region string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%s", accountID, roleName, region)))
	return fmt.Sprintf("%x", h)
}

func cachePath(key string) string {
	dir := filepath.Join(homeDir(), ".aws", "cli", "cache")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, fmt.Sprintf("saml-%s.json", key))
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return os.Getenv("HOME")
}

// Load returns cached credentials if they exist and are still valid (>5 min remaining).
func Load(accountID, roleName, region string) (*Credentials, bool) {
	key := cacheKey(accountID, roleName, region)
	path := cachePath(key)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, false
	}

	expiration, err := time.Parse(time.RFC3339, creds.Expiration)
	if err != nil {
		return nil, false
	}

	// Consider valid if more than 5 minutes remaining
	if time.Until(expiration) <= 5*time.Minute {
		return nil, false
	}

	return &creds, true
}

// Save writes credentials to the cache.
func Save(accountID, roleName, region string, creds *Credentials) error {
	key := cacheKey(accountID, roleName, region)
	path := cachePath(key)

	data, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}
