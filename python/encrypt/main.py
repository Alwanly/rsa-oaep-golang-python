from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from binascii import hexlify

# Function to read the public key from a .pem file
def read_public_key_from_file(filename):
    with open(filename, 'rb') as f:
        key = RSA.import_key(f.read())
    return key

# Read the public key from the .pem file
public_key = read_public_key_from_file("../cert/public_key.pem")

# Get the plaintext message from user input
plaintext = input("Enter the plaintext message: ")

# Encrypt the plaintext message using the public key
cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256, label=b"test")
ciphertext = cipher_rsa.encrypt(plaintext.encode('utf-8'))

# Display the encrypted result as a hexadecimal string
ciphertext_hex = hexlify(ciphertext).decode('utf-8')
print("Encrypted (hex):", ciphertext_hex)