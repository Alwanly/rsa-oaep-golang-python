package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Function to read the public key from a .pem file
func readPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)

	var pub interface{}
	switch block.Type {
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the message to encrypt: ")
	inputString, _ := reader.ReadString('\n')

	publicKey, err := readPublicKeyFromFile("../cert/public_key.pem")
	if err != nil {
		fmt.Println("Error reading public key:", err)
		return
	}

	message := []byte(inputString)
	label := []byte("test")
	hash := sha256.New()

	// Encrypt the message using the public key and OAEP padding
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, message, label)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	fmt.Printf("Ciphertext (hex): %x\n", ciphertext)
}
