package go_beaxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// base64ToBigInt will base64 decode the input and populate *big.Int
func base64ToBigInt(input string) (*big.Int, error) {
	i := new(big.Int)
	intStr, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	i.SetBytes([]byte(intStr))
	return i, nil
}

// generateRandomBytes returns securely generated random bytes.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// parsePrivateKey will try to parse the given keyContent into a PKCS8 rsa.PrivateKey
func parsePrivateKey(keyContent string) (*rsa.PrivateKey, error) {
	newK := fmt.Sprintf(`-----BEGIN PRIVATE KEY-----
%s
-----END PRIVATE KEY-----`, keyContent)

	block, _ := pem.Decode([]byte(newK))
	if block == nil {
		return nil, fmt.Errorf("no valid PEM data found")
	} else if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected PRIVATE KEY, got %s", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("")
	}
	return rsaKey, nil
}

// getJson will parse the http response to the target struct
func getJson(response *http.Response, target interface{}) error {
	defer response.Body.Close()
	return json.NewDecoder(response.Body).Decode(target)
}

// getNonce will return the current timestamp in milli seconds
func getNonce() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func toTimestampMilliseconds(t time.Time) int64 {
	return t.UnixNano() / int64(time.Millisecond)
}
