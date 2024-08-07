go-encrypt:
	go run ./go/encrypt/main.go

go-decrypt:
	go run ./go/decrypt/main.go

python-encrypt:
	python3 ./python/encrypt/main.py

python-decrypt:
	python3 ./python/decrypt/main.py

venv:
	python3 -m venv venv

install: venv
	source venv/bin/activate && pip install pycryptodome

generate-cert: private_key.pem public_key.pem

private_key.pem:
	openssl genpkey -algorithm RSA -out ./cert/private_key.pem -pkeyopt rsa_keygen_bits:1024

public_key.pem: private_key.pem
	openssl rsa -in ./cert/private_key.pem -pubout -out ./cert/public_key.pem

.PHONY: go-encrypt go-decrypt python-encrypt python-decrypt install venv generate-cert