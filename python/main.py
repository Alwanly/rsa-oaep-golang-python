from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from binascii import unhexlify

# Function to read the private key from a .pem file
def read_private_key_from_file(filename):
    with open(filename, 'rb') as f:
        key = RSA.import_key(f.read())
    return key

# Read the private key from the .pem file
private_key = read_private_key_from_file("../cert/private_key.pem")

# Get the ciphertext from user input
ciphertext_hex = input("Enter the ciphertext (hex): ")
ciphertext = unhexlify(ciphertext_hex)

# Decrypt the ciphertext using the private key and display the result as a UTF-8 encoded string 
cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256,label=b"test")
try:
    decrypted = cipher_rsa.decrypt(ciphertext)
    # Display the decrypted result as a UTF-8 encoded string
    print("Decrypted:", decrypted.decode("utf-8"))
except ValueError as e:
    print("Decryption failed:", str(e))