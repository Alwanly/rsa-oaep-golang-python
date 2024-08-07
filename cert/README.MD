#RSA Private and Public Key


```
private_key.pem:
	openssl genpkey -algorithm RSA -out ./cert/private_key.pem -pkeyopt rsa_keygen_bits:1024

public_key.pem: private_key.pem
	openssl rsa -in ./cert/private_key.pem -pubout -out ./cert/public_key.pem
```