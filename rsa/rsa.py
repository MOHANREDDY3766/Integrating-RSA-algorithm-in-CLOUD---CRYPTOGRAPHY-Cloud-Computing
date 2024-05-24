# rsa.py
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(private_key, encrypted_message):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()

# Example Usage
if __name__ == "__main__":
    private_key, public_key = generate_key_pair()
    print("Private Key:\n", private_key.decode())
    print("Public Key:\n", public_key.decode())

    message = "Hello, World!"
    encrypted_message = encrypt_message(public_key, message)
    print("Encrypted Message:\n", encrypted_message)

    decrypted_message = decrypt_message(private_key, encrypted_message)
    print("Decrypted Message:", decrypted_message)
