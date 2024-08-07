# RSA OAEP With Golang and Python

## Pre-requisites

1. **Golang**: Ensure you have Go installed. You can download it from [golang.org](https://golang.org/dl/).
2. **Python**: Ensure you have Python 3 installed. You can download it from [python.org](https://www.python.org/downloads/).
3. **OpenSSL**: Ensure you have OpenSSL installed. You can install it using Homebrew on macOS:
   ```sh
   brew install openssl
   ```
4. Virtual Environment: Ensure you have venv module available for creating virtual environments in Python.

## Step-by-Step Instructions

1. Clone the repository
```
git clone https://github.com/yourusername/rsaoaep-go-python.git
cd rsaoaep-go-python
```

2. Setup Python Virtual
```
make venv
```
3.  Install Python Dependencies
```
make install
```
4. Generate RSA Keys and Certificate
```
make generate-cert
```
5. Run Golang Encryption and Decryption

To encrypt data using Golang:
```
make go-encrypt
go run ./go/encrypt/main.go
Enter the message to encrypt: test encrypt
chipperText (base64): KzVkgN+FtWJYwZJaS6tj99yz3Yzef8B3/w9kOeyasQb/ZH9x/cDm5N4HZSTpk2AdZ5TTttuoyVR5fFfcrzgoSlEDolq++3L1LYv4s2Zd+ryp3TsZ59bjNXph2jSgPnHQeticCEaBoK0gcKOAjzJc1ffloJUYt85ZIvhD0WgaXg8=

```
To decrypt data using Golang:
```
make go-decrypt
go run ./go/decrypt/main.go
Enter the chipperText (base64): KzVkgN+FtWJYwZJaS6tj99yz3Yzef8B3/w9kOeyasQb/ZH9x/cDm5N4HZSTpk2AdZ5TTttuoyVR5fFfcrzgoSlEDolq++3L1LYv4s2Zd+ryp3TsZ59bjNXph2jSgPnHQeticCEaBoK0gcKOAjzJc1ffloJUYt85ZIvhD0WgaXg8=
Decrypted message: test encrypt
```
6. Run Python Encryption and Decryption

To encrypt data using Python:
```
make python-encrypt
python3 ./python/encrypt/main.py
Enter the plaintext message: test python
Encrypted (Base64): aYZRG0BAZxWI2oWXHr7bw5bK650w+6HI+hVBtpNbjF+1Zje8mG/dQSaylBVAxtZs/vx7iQgAlD43klqsPgoRfG4dSz/fP1hriEHmw7b4shCs+GjnQRP2FY9vsYo/dBUpKDRu+Tex89B8oMDjC3PWQOY3UmvXml5j/TrrpwLtHRg=
```
To decrypt data using Python:
```
make python-decrypt
python3 ./python/decrypt/main.py
Enter the ciphertext (base64): aYZRG0BAZxWI2oWXHr7bw5bK650w+6HI+hVBtpNbjF+1Zje8mG/dQSaylBVAxtZs/vx7iQgAlD43klqsPgoRfG4dSz/fP1hriEHmw7b4shCs+GjnQRP2FY9vsYo/dBUpKDRu+Tex89B8oMDjC3PWQOY3UmvXml5j/TrrpwLtHRg=
Decrypted: test python
```

### Notes
- The generated keys and certificate will be in the project directory.
- Ensure you have the necessary permissions to execute the make commands.