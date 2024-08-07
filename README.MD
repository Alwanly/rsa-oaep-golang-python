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

```
To decrypt data using Golang:
```
make go-decrypt
```
6. Run Python Encryption and Decryption

To encrypt data using Python:
```
make python-encrypt
```
To decrypt data using Python:
```
make python-decrypt
```

### Notes
- The generated keys and certificate will be in the project directory.
- Ensure you have the necessary permissions to execute the make commands.