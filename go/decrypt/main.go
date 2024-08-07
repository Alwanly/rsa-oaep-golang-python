package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// Function to read the private key from a .pem file
func readPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || (block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY") {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	var priv *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	} else if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		priv, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}

	return priv, nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the chipperText (base64): ")
	chipperTextBase64, _ := reader.ReadString('\n')
	chipperTextBase64 = strings.TrimSpace(chipperTextBase64) // Trim any whitespace or newline characters

	chipperText, err := base64.StdEncoding.DecodeString(chipperTextBase64)
	if err != nil {
		fmt.Println("Error decoding chipperText:", err)
		return
	}

	privateKey, err := readPrivateKeyFromFile("./cert/private_key.pem")
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return
	}

	label := []byte("test")
	hash := sha256.New()

	// Decrypt the chipperText using the private key and OAEP padding
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, chipperText, label)
	if err != nil {
		fmt.Println("Error decrypting chipperText:", err)
		return
	}

	fmt.Printf("Decrypted message: %s\n", plaintext)
}
